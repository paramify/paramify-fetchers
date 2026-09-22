#!/usr/bin/env python3
"""
Splunk Audit Event Types and Non-Repudiation Field Coverage

Runs SPL against the audit indexes of one Splunk deployment and reports what is
ACTUALLY being logged: every distinct event type present over a real time
window, and — per event type — how much of that traffic carries each of the
seven non-repudiation elements the capability narrative claims audit records
enforce (KSI-MLA-LET).

This is the only fetcher on the Splunk slate that runs a search rather than
reading configuration, and that difference is the point. The siblings prove a
retention setting, a role's reach, an alert's schedule: all of them prove what
the deployment is CONFIGURED to do. This one proves what it DID. A claim that
audit records carry the actor, the outcome and the source is not a claim about
a settings page; it is a claim about the records, and the only way to check it
is to read them.

Five things worth knowing before changing this file:

1. **The search is a `exec_mode=oneshot` POST, not create-poll-fetch.**
   `POST /services/search/jobs` with `exec_mode=oneshot` runs the search
   synchronously and returns the result rows in the body of that same response.
   The response carries no search id, so there is no `dispatchState` to poll
   and no results endpoint to call afterwards. The asynchronous shape (POST to
   create, GET `/search/jobs/<sid>` until `dispatchState` is `DONE`, then GET
   `/search/jobs/<sid>/results/`) is the one the documentation leads with and it
   works, but it is three round trips and a poll loop that has to be bounded.
   Oneshot is one call with neither. MEASURED working on Splunk Enterprise
   10.4.3.

   A oneshot search does still register a **transient** job on the deployment —
   MEASURED: it appears in `GET /services/search/jobs` with a numeric sid and
   `dispatchState: DONE`, and Splunk reaps it on its own ttl. The fetcher cannot
   delete it explicitly because the oneshot response never hands back the sid,
   and it does not need to: the jobs do not accumulate. Worth knowing rather
   than being surprised by, since it means running this fetcher is briefly
   visible in the job list.

2. **`output_mode=json` is passed on the call that RETURNS the rows.**
   Splunk's search results default to XML, and the classic failure here is
   passing `output_mode=json` when creating a job and then reading the results
   endpoint without it, which returns XML to a `response.json()`. With oneshot
   the create call and the results call are the same call, so one parameter
   covers both — which is a second, quieter reason to prefer it.

3. **The search is bounded twice.** The HTTP read timeout bounds the socket and
   Splunk's own `max_time` bounds the search server-side, both from the same
   configured value. Either alone leaves a hole: an HTTP timeout abandons a
   search that keeps burning the deployment's resources, and `max_time` alone
   does not protect against a stalled connection.

4. **Field presence is not field meaning.** `user` is present on 100% of the
   records on the deployment this was built against, and holds the literal
   string `n/a` on 87% of them, because Splunk's filesystem-change audit records
   have no principal to name. A fetcher that counted presence alone would report
   "every audit record carries an associated identity" and be exactly wrong
   about the element the narrative cares most about. Every field is therefore
   counted twice — `present` and `meaningful` — and the roll-ups use whichever
   of the two the element actually requires, which is stated per element.

5. **Every verdict here asserts a POSITIVE**, which is the vacuous-truth trap
   the sibling `splunk_saved_search_alerts` hit first: "every event type carries
   a user field" is true when there are no event types. So `scope_is_assessable`
   requires events to have actually been observed, and every positive verdict is
   AND-ed with it. Inside the roll-up the same guard is local — each
   `every_event_type_*` flag is `bool(types) and ...`, so an empty set is false
   rather than true.

One honesty note that belongs in the evidence and not only here: running this
fetcher writes records to `_audit`, because Splunk audits searches. The search
this fetcher runs will appear in its own results. `self_observation_note` in the
payload says so rather than leaving a reader to wonder.
"""

import fnmatch
import json
import logging
import os
import re
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

# The shared failure-reporting helper lives in fetchers/_lib/ — the same import
# mechanism as a category `_shared` module, one directory up.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1] / "_lib"))

from fetcher_status import report_failure  # noqa: E402

logger = logging.getLogger("splunk_audit_event_types")

# Splunk's own fixed-name audit index. Present on every deployment under that
# exact name, so defaulting to it is a platform fact rather than an assumption
# about any particular installation.
DEFAULT_AUDIT_INDEX = "_audit"

# The bucket an event lands in when it carries no `action` field at all. Such
# events are NOT dropped: a record with no event type is precisely a record
# failing the first of the seven elements, and silently excluding it would turn
# a finding into a clean sheet.
NO_EVENT_TYPE = "(no event type field)"

# Values that occupy a field without identifying anything. Splunk writes `n/a`
# into `user` on records with no principal — a filesystem change detected by the
# platform itself, for instance. Treating those as an identity is the single
# easiest way to over-report non-repudiation, and it is the same normalisation
# splunk_role_index_access applies when it reads `srchFilter: "*"` as no filter.
PLACEHOLDER_VALUES = {"n/a", "na", "none", "null", "unknown", "undefined", "-", "--"}

# The Splunk fields whose presence is measured, per event type. Keep this list
# and ELEMENT_FIELDS below in step: every element must be readable from fields
# named here, because an element is never reported as covered without naming the
# field it was read from.
MEASURED_FIELDS = [
    "action",
    "timestamp",
    "host",
    "splunk_server",
    "clientip",
    "src",
    "info",
    "object",
    "search",
    "user",
]

# The narrative's seven elements, mapped onto the Splunk fields that carry them.
#
# `fields`     — any one of these carrying a value covers the element.
# `require`    — "meaningful" when a placeholder must not count (identity), or
#                "present" when the field merely existing is the evidence.
# `scoped`     — True for an element that is only assessed within the privileged
#                command scope, because it does not apply to every record.
ELEMENT_FIELDS: Dict[str, Dict[str, Any]] = {
    "event_type": {
        "fields": ["action"],
        "require": "meaningful",
        "scoped": False,
        "narrative_term": "event type",
        "note": (
            "The `action` field is Splunk's name for what happened — `login "
            "attempt`, `edit_roles`, `search`. Required to be meaningful rather "
            "than merely present: a record whose action is empty or a "
            "placeholder records that something happened without recording what."
        ),
    },
    "when": {
        "fields": ["timestamp"],
        "require": "present",
        "scoped": False,
        "narrative_term": "when",
        "note": (
            "Measured from the `timestamp` field PARSED OUT OF the audit record "
            "itself, not from Splunk's `_time`. `_time` is set on every indexed "
            "event by construction — Splunk cannot store an event without it — "
            "so measuring `_time` would report 100% coverage on any deployment "
            "whatever and prove nothing. `timestamp` is the time the audited "
            "system wrote into the record, which is the one the element means."
        ),
    },
    "where": {
        "fields": ["host", "splunk_server"],
        "require": "meaningful",
        "scoped": False,
        "narrative_term": "where",
        "note": (
            "`host` (the host the record came from) or `splunk_server` (the "
            "Splunk instance that recorded it). This is where the event "
            "OCCURRED, which on a single-instance deployment is the same value "
            "for every record; `where_distinct_values` is reported so a reader "
            "can see whether the field is discriminating or constant."
        ),
    },
    "source": {
        "fields": ["clientip", "src"],
        "require": "meaningful",
        "scoped": False,
        "narrative_term": "source",
        "note": (
            "The network origin of the request — `clientip` on Splunk's own "
            "audit records, `src` on records normalised to the Common "
            "Information Model. This is the element most likely to be missing: "
            "Splunk records it on authentication events but not on most "
            "internal or platform-generated ones, so a low figure here is a "
            "real measurement and not a collection defect."
        ),
    },
    "outcome": {
        "fields": ["info"],
        "require": "meaningful",
        "scoped": False,
        "narrative_term": "outcome",
        "note": (
            "The `info` field carries the disposition — `granted`, `denied`, "
            "`succeeded`, `failed`, `completed`, `expired`. `outcome_values` "
            "lists the distinct values observed per event type so a reader can "
            "confirm the field genuinely records success and failure rather "
            "than always reading the same way."
        ),
    },
    "privileged_command_text": {
        "fields": ["search", "object"],
        "require": "meaningful",
        "scoped": True,
        "narrative_term": "full-text of privileged commands",
        "note": (
            "`search` carries the full SPL text of an executed search; `object` "
            "carries the configuration object a privileged change acted on. "
            "Assessed ONLY within `privileged_command_scope`, because the "
            "element does not apply to a record that is not a command — a "
            "filesystem-change record has no command text to carry, and "
            "counting it as a failure would report a misleading coverage figure "
            "for the deployment as a whole. The REST endpoint path that "
            "sometimes appears inside `info` is deliberately NOT counted: an "
            "endpoint is what was called, not the full text of the command, and "
            "under-claiming is the safe direction."
        ),
    },
    "identity": {
        "fields": ["user"],
        "require": "meaningful",
        "scoped": False,
        "narrative_term": "associated identities",
        "note": (
            "The `user` field, required to name an actual principal. This is the "
            "element where presence and meaning diverge most sharply: Splunk "
            "writes the literal string `n/a` into `user` on records with no "
            "principal, so the field is present on effectively every record "
            "while identifying nobody on many of them. Both figures are "
            "reported — `identity_field_present_*` alongside the covered counts "
            "— because the gap between them IS the finding."
        ),
    },
}


def current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sanitize_for_filename(value: str) -> str:
    sanitized = value.replace("://", "_").replace("/", "_").replace(":", "_")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", sanitized)


def env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() not in {"false", "0", "no", "off"}


def csv_env(name: str, default: str = "") -> List[str]:
    return [v.strip() for v in os.environ.get(name, default).split(",") if v.strip()]


def int_env(name: str, default: int) -> int:
    try:
        value = int(str(os.environ.get(name, "")).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def build_session(token: str, username: str, password: str, verify_ssl: bool) -> requests.Session:
    """Bearer token if we have one, HTTP basic otherwise.

    Splunk Cloud effectively requires the token; basic auth is the Enterprise
    and sandbox path. Callers guarantee one of the two is present.
    """
    session = requests.Session()
    session.verify = verify_ssl
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    else:
        session.auth = (username, password)
    return session


def get_json(session: requests.Session, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    merged = {"output_mode": "json", **params}
    response = session.get(url, params=merged, timeout=120)
    if response.status_code in (401, 403):
        raise PermissionError(f"{response.status_code} from {url}: {response.text[:300]}")
    if response.status_code != 200:
        raise RuntimeError(f"{response.status_code} from {url}: {response.text[:300]}")
    return response.json()


def to_int(value: Any) -> Optional[int]:
    """splunkd returns every number as a string, including stats output."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def to_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def as_list(value: Any) -> List[str]:
    """splunkd omits empty multivalue fields and collapses single ones to a str."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def pct(numerator: int, denominator: int) -> Optional[float]:
    if not denominator:
        return None
    return round(numerator * 100.0 / denominator, 2)


def epoch_to_iso(value: Any) -> Optional[str]:
    seconds = to_float(value)
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# SPL
# --------------------------------------------------------------------------


def _spl_placeholder_clause(field: str) -> str:
    """The `not a placeholder` half of a meaningful-value test, as SPL."""
    return " AND ".join(f'lower({field})!="{p}"' for p in sorted(PLACEHOLDER_VALUES))


def build_spl(indexes: List[str], include_samples: bool) -> str:
    """One search, aggregating by event type.

    Generated from MEASURED_FIELDS rather than written out by hand so that the
    SPL and the element map cannot drift apart: adding a field to the list adds
    its two counters to the search, its two columns to every event type, and
    nothing else needs touching.

    One search rather than several is deliberate. Every extra search is another
    job on the deployment, another set of records written into the very index
    being measured, and another failure mode. Everything the roll-ups need is
    derivable in Python from this one result set.
    """
    index_clause = " OR ".join(f'index={idx}' for idx in indexes)

    evals = [
        # A record with no action is kept and bucketed, not dropped — see
        # NO_EVENT_TYPE. `stats by action` would discard it silently, turning a
        # record that fails the first element into a record that never existed.
        f'event_type=if(isnotnull(action) AND action!="", action, "{NO_EVENT_TYPE}")',
        # The identity VALUE with placeholders nulled out, so `dc()` counts
        # principals rather than counting "n/a" as a person.
        f'named_user=if(isnotnull(user) AND user!="" AND {_spl_placeholder_clause("user")}, user, null())',
    ]
    for field in MEASURED_FIELDS:
        evals.append(f'p_{field}=if(isnotnull({field}) AND {field}!="", 1, 0)')
        evals.append(
            f'm_{field}=if(isnotnull({field}) AND {field}!="" '
            f'AND {_spl_placeholder_clause(field)}, 1, 0)'
        )
    # Length of the privileged-command text, which is how the evidence shows the
    # FULL text is captured rather than a truncated stub, without reproducing
    # any of that text when samples are switched off.
    evals.append('cmd_len=if(isnotnull(search) AND search!="", len(search), null())')
    # The outcome as its leading word. Splunk writes `info` values such as
    # `granted REST: /properties/server/...` and `Successfully validated
    # tokenId: 0099b58...`, so the raw field has hundreds of distinct values per
    # event type — a per-request detail rather than a disposition. The first
    # token is the disposition (`granted`, `denied`, `succeeded`, `failed`,
    # `completed`, `expired`), which is what an assessor checking that the field
    # records failure as well as success needs, and it keeps identifiers and
    # endpoint paths out of the evidence file.
    evals.append('outcome_class=if(isnotnull(info) AND info!="", mvindex(split(info, " "), 0), null())')

    aggs = ["count as events"]
    for field in MEASURED_FIELDS:
        aggs.append(f"sum(p_{field}) as p_{field}")
        aggs.append(f"sum(m_{field}) as m_{field}")
    aggs.extend(
        [
            "min(_time) as first_seen_epoch",
            "max(_time) as last_seen_epoch",
            "dc(named_user) as distinct_identities",
            "values(named_user) as identities",
            "values(outcome_class) as outcome_values",
            "dc(info) as distinct_outcome_detail_values",
            "values(sourcetype) as sourcetypes",
            "values(index) as indexes",
            "values(host) as hosts",
            "max(cmd_len) as cmd_len_max",
            "avg(cmd_len) as cmd_len_avg",
        ]
    )
    if include_samples:
        # Truncated hard at 200 characters, and only when explicitly enabled —
        # a privileged command's full text is the field most likely to carry
        # data that should not leave the deployment inside an evidence file.
        evals.append('cmd_sample=if(isnotnull(search) AND search!="", substr(search, 1, 200), null())')
        aggs.append("values(cmd_sample) as command_samples")

    return (
        f"search ({index_clause})\n"
        f"| eval {', '.join(evals)}\n"
        f"| stats {', '.join(aggs)} by event_type\n"
        f"| sort - events"
    )


def run_oneshot_search(
    session: requests.Session, host: str, spl: str, window: str, timeout_secs: int
) -> Dict[str, Any]:
    """Execute SPL synchronously and return the parsed result document.

    `exec_mode=oneshot` makes `POST /services/search/jobs` run the search and
    return its rows in the same response — no search id, no `dispatchState`
    poll, no results endpoint, nothing to clean up afterwards. `output_mode=json`
    is on this call because this call is the one that returns the rows; Splunk's
    results default to XML and passing the parameter only when creating an
    asynchronous job is the classic way to end up handing XML to a JSON parser.

    Bounded at both ends: `max_time` stops the search inside Splunk, the HTTP
    read timeout stops us waiting on it. A search that hits either is reported
    as a diagnosed timeout, never as an empty result set.
    """
    url = f"{host.rstrip('/')}/services/search/jobs"
    payload = {
        "search": spl,
        "exec_mode": "oneshot",
        "output_mode": "json",
        # Return every aggregated row. splunkd's convention, the same one the
        # sibling fetchers use on their collection endpoints.
        "count": 0,
        "earliest_time": window,
        "latest_time": "now",
        # Splunk's own bound on how long the search may run before it is
        # finalized, in seconds.
        "max_time": timeout_secs,
        # Run with the caller's own knowledge objects. The SPL here references
        # no macro, event type or lookup, so nothing depends on this — but
        # VERIFIED rather than assumed: the same search issued against
        # /servicesNS/-/-/search/jobs returned an identical event count, so the
        # namespace under-reporting that affects app-scoped knowledge objects
        # (and bit splunk_saved_search_alerts) does not affect a search over raw
        # index data.
        "adhoc_search_level": "smart",
    }
    try:
        response = session.post(url, data=payload, timeout=timeout_secs)
    except requests.exceptions.Timeout as exc:
        raise TimeoutError(
            f"Search exceeded the {timeout_secs}s bound and was abandoned: {exc}. "
            f"Narrow SPLUNK_AUDIT_SEARCH_WINDOW or raise "
            f"SPLUNK_AUDIT_SEARCH_TIMEOUT_SECS (keeping it below runtime.timeout)."
        ) from exc

    if response.status_code in (401, 403):
        raise PermissionError(
            f"{response.status_code} from {url}: {response.text[:300]}. Running a "
            f"search needs the `search` capability and read access to the audit "
            f"indexes; a role that can read index CONFIGURATION cannot "
            f"necessarily read index CONTENT."
        )
    if response.status_code != 200:
        raise RuntimeError(f"{response.status_code} from {url}: {response.text[:300]}")

    try:
        return response.json()
    except ValueError as exc:
        # Almost always means output_mode did not take and Splunk returned its
        # default XML. Say that, rather than surfacing a bare JSON parse error.
        raise RuntimeError(
            f"Search results were not JSON ({exc}). Splunk returns search "
            f"results as XML by default; output_mode=json must be set on the "
            f"call that returns the rows. First 200 bytes: {response.text[:200]}"
        ) from exc


# --------------------------------------------------------------------------
# Shaping and roll-up
# --------------------------------------------------------------------------


def describe_event_type(row: Dict[str, Any], privileged_patterns: List[str]) -> Dict[str, Any]:
    """One observed event type, with per-field presence and per-element coverage."""
    name = str(row.get("event_type") or NO_EVENT_TYPE)
    events = to_int(row.get("events")) or 0

    fields: Dict[str, Any] = {}
    for field in MEASURED_FIELDS:
        present = to_int(row.get(f"p_{field}")) or 0
        meaningful = to_int(row.get(f"m_{field}")) or 0
        fields[field] = {
            "events_with_field_present": present,
            "events_with_meaningful_value": meaningful,
            "present_pct": pct(present, events),
            "meaningful_pct": pct(meaningful, events),
            # A field present on every record but meaningful on none is the
            # `user: "n/a"` shape, and it is worth flagging by name rather than
            # leaving a reader to subtract two numbers.
            "present_but_never_meaningful": present > 0 and meaningful == 0,
        }

    elements: Dict[str, Any] = {}
    for element, spec in ELEMENT_FIELDS.items():
        key = "events_with_meaningful_value" if spec["require"] == "meaningful" else "events_with_field_present"
        # Any one of the element's fields carrying a value covers it. The counts
        # are per-field sums so this is an upper bound when two of them are
        # populated on different records; `covering_fields` names which ones
        # actually contributed, so the reader can see what the number rests on.
        best = max((fields[f][key] for f in spec["fields"]), default=0)
        covered = min(best, events)
        elements[element] = {
            "narrative_term": spec["narrative_term"],
            "read_from_fields": list(spec["fields"]),
            "covering_fields": [f for f in spec["fields"] if fields[f][key] > 0],
            "requires": spec["require"],
            "events_covered": covered,
            "coverage_pct": pct(covered, events),
            "fully_covered": events > 0 and covered == events,
            "assessed_only_in_privileged_scope": bool(spec["scoped"]),
        }

    return {
        "event_type": name,
        "events": events,
        "is_privileged_command": matches_any(name, privileged_patterns),
        "first_seen": epoch_to_iso(row.get("first_seen_epoch")),
        "last_seen": epoch_to_iso(row.get("last_seen_epoch")),
        "indexes": sorted(as_list(row.get("indexes"))),
        "sourcetypes": sorted(as_list(row.get("sourcetypes"))),
        "hosts": sorted(as_list(row.get("hosts"))),
        "distinct_identities": to_int(row.get("distinct_identities")) or 0,
        "identities": sorted(as_list(row.get("identities"))),
        "outcome_values": sorted(as_list(row.get("outcome_values"))),
        "distinct_outcome_detail_values": to_int(row.get("distinct_outcome_detail_values")) or 0,
        "command_text_max_length": to_int(row.get("cmd_len_max")),
        "command_text_avg_length": (
            round(to_float(row.get("cmd_len_avg")), 1)
            if to_float(row.get("cmd_len_avg")) is not None
            else None
        ),
        "command_samples": sorted(as_list(row.get("command_samples"))),
        "fields": fields,
        "elements": elements,
    }


def matches_any(name: str, patterns: List[str]) -> bool:
    """Glob match, because Splunk names its audit actions systematically.

    `edit_*` catching `edit_roles`, `edit_index` and `edit_storage_passwords` is
    the difference between a knob that stays correct and one that goes stale the
    first time Splunk adds an action.
    """
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def summarize(event_types: List[Dict[str, Any]], scoped: bool) -> Dict[str, Any]:
    """Element coverage roll-up over whichever set of event types was handed in.

    `scoped` selects whether the elements that only apply to privileged commands
    are assessed. Outside that scope they are reported as not assessed rather
    than as failed, because a filesystem-change record has no command text to
    carry and scoring it against that element would be measuring the wrong
    thing.

    Every verdict below asserts a POSITIVE, and a positive over an empty set is
    vacuously true. `bool(event_types) and ...` is the local half of the guard;
    `scope_is_assessable` is the half the caller AND-s in.
    """
    total_events = sum(t["events"] for t in event_types)
    elements: Dict[str, Any] = {}

    for element, spec in ELEMENT_FIELDS.items():
        if spec["scoped"] and not scoped:
            elements[element] = {
                "narrative_term": spec["narrative_term"],
                "read_from_fields": list(spec["fields"]),
                "assessed": False,
                "not_assessed_because": (
                    "This element applies only to records that ARE privileged "
                    "commands. It is assessed in privileged_command_scope, which "
                    "requires SPLUNK_PRIVILEGED_EVENT_TYPES to be set."
                ),
            }
            continue

        covered_events = sum(t["elements"][element]["events_covered"] for t in event_types)
        full = [t for t in event_types if t["elements"][element]["fully_covered"]]
        partial = [
            t
            for t in event_types
            if not t["elements"][element]["fully_covered"]
            and t["elements"][element]["events_covered"] > 0
        ]
        absent = [t for t in event_types if t["elements"][element]["events_covered"] == 0]
        elements[element] = {
            "narrative_term": spec["narrative_term"],
            "read_from_fields": list(spec["fields"]),
            "requires": spec["require"],
            "assessed": True,
            "events_covered": covered_events,
            "events_total": total_events,
            "event_coverage_pct": pct(covered_events, total_events),
            "event_types_fully_covered": len(full),
            "event_types_partially_covered": len(partial),
            "event_types_not_covered": len(absent),
            "event_types_total": len(event_types),
            "event_types_not_covered_names": sorted(str(t["event_type"]) for t in absent),
            "event_types_partially_covered_names": sorted(str(t["event_type"]) for t in partial),
            # THE verdict. `bool(event_types)` is not decoration: without it
            # "every event type carries this element" is true of no event types.
            "every_event_type_fully_covered": bool(event_types) and len(full) == len(event_types),
            "every_event_is_covered": bool(total_events) and covered_events == total_events,
            "note": spec["note"],
        }

    assessed = [e for e in elements.values() if e.get("assessed")]
    return {
        "event_types_observed": len(event_types),
        "event_types_observed_names": sorted(str(t["event_type"]) for t in event_types),
        "events_observed": total_events,
        "distinct_identities_observed": len(
            {i for t in event_types for i in t["identities"]}
        ),
        "identities_observed": sorted({i for t in event_types for i in t["identities"]}),
        "elements": elements,
        "elements_assessed": sorted(
            k for k, v in elements.items() if v.get("assessed")
        ),
        "elements_fully_covered": sorted(
            k for k, v in elements.items() if v.get("every_event_type_fully_covered")
        ),
        "elements_not_fully_covered": sorted(
            k
            for k, v in elements.items()
            if v.get("assessed") and not v.get("every_event_type_fully_covered")
        ),
        # The headline. True only when every assessed element is fully covered on
        # every observed event type — and `bool(event_types)` keeps an empty
        # deployment from reading as a clean sheet.
        "all_assessed_elements_fully_covered": bool(event_types)
        and bool(assessed)
        and all(e["every_event_type_fully_covered"] for e in assessed),
        # Reported alongside, because the gap between the two is the finding.
        "identity_field_present_events": sum(
            t["fields"]["user"]["events_with_field_present"] for t in event_types
        ),
        "identity_meaningful_events": sum(
            t["fields"]["user"]["events_with_meaningful_value"] for t in event_types
        ),
    }


def collect(
    session: requests.Session,
    host: str,
    indexes: List[str],
    privileged_patterns: List[str],
    window: str,
    timeout_secs: int,
    include_samples: bool,
) -> Dict[str, Any]:
    base = host.rstrip("/")
    api_failures: List[Dict[str, str]] = []

    server = {}
    try:
        info = get_json(session, f"{base}/services/server/info", {})
        content = (info.get("entry") or [{}])[0].get("content", {})
        server = {
            "version": content.get("version"),
            "product_type": content.get("product_type"),
            "license_state": content.get("licenseState"),
            "server_name": content.get("serverName"),
            "mode": content.get("mode"),
        }
    except Exception as exc:  # server/info is context, not the evidence itself
        api_failures.append(
            {"operation": "GET /services/server/info", "type": type(exc).__name__, "message": str(exc)}
        )

    # Splunk filters search results by the indexes the CALLER's roles allow, so
    # the identity that ran this search is part of the evidence — the same
    # reason splunk_role_index_access and splunk_saved_search_alerts record it,
    # and sharper here: a role without `srchIndexesAllowed` covering an audit
    # index gets an empty result set, not an error.
    caller = {}
    try:
        ctx = get_json(session, f"{base}/services/authentication/current-context", {})
        content = (ctx.get("entry") or [{}])[0].get("content", {})
        caller = {
            "username": content.get("username"),
            "roles": as_list(content.get("roles")),
            "capability_count": len(as_list(content.get("capabilities"))),
        }
    except Exception as exc:
        api_failures.append(
            {
                "operation": "GET /services/authentication/current-context",
                "type": type(exc).__name__,
                "message": str(exc),
            }
        )

    spl = build_spl(indexes, include_samples)
    document = run_oneshot_search(session, base, spl, window, timeout_secs)

    # Splunk reports search-time problems in `messages`, with a 200 status. A
    # FATAL there means the search did not run, which must not be mistaken for a
    # deployment that has no audit events.
    messages = [
        {"type": str(m.get("type")), "text": str(m.get("text"))}
        for m in (document.get("messages") or [])
    ]
    fatal = [m for m in messages if m["type"].upper() in {"FATAL", "ERROR"}]
    if fatal:
        raise RuntimeError(
            "Splunk returned an error for the search: "
            + "; ".join(m["text"] for m in fatal)
        )

    rows = document.get("results") or []
    event_types = [describe_event_type(r, privileged_patterns) for r in rows]

    observed_indexes = sorted({i for t in event_types for i in t["indexes"]})
    empty_indexes = [i for i in indexes if i not in observed_indexes]
    first_seen = sorted(t["first_seen"] for t in event_types if t["first_seen"])
    last_seen = sorted(t["last_seen"] for t in event_types if t["last_seen"])

    # Two roll-ups, mirroring the three sibling Splunk fetchers. `summary` is the
    # completeness view over every event type observed. `privileged_command_scope`
    # is the one that speaks to the "full-text of privileged commands" half of
    # the narrative, which cannot be assessed over records that are not commands.
    summary = summarize(event_types, scoped=False)
    summary.update(
        {
            "window_requested_earliest": window,
            "window_requested_latest": "now",
            "window_observed_earliest": first_seen[0] if first_seen else None,
            "window_observed_latest": last_seen[-1] if last_seen else None,
            "indexes_searched": sorted(indexes),
            "indexes_with_events": observed_indexes,
            "indexes_named_but_empty": sorted(empty_indexes),
            "sourcetypes_observed": sorted({s for t in event_types for s in t["sourcetypes"]}),
            "hosts_observed": sorted({h for t in event_types for h in t["hosts"]}),
            "where_distinct_values": len({h for t in event_types for h in t["hosts"]}),
            # The guard. Positive assertions over an empty result set are
            # vacuously true, and an empty result set is exactly what a
            # misconfigured index name or an under-privileged service account
            # produces — neither of which should ever read as a pass.
            "scope_is_assessable": bool(event_types) and summary["events_observed"] > 0,
        }
    )
    for verdict in ("all_assessed_elements_fully_covered",):
        summary[verdict] = bool(summary[verdict]) and summary["scope_is_assessable"]

    in_scope = [t for t in event_types if t["is_privileged_command"]]
    present_types = {str(t["event_type"]) for t in event_types}
    unmatched = [
        p
        for p in privileged_patterns
        if not any(fnmatch.fnmatchcase(n, p) for n in present_types)
    ]
    scope: Dict[str, Any] = {
        "privileged_event_types_configured": bool(privileged_patterns),
        "privileged_event_type_patterns": sorted(privileged_patterns),
        "patterns_matching_nothing_observed": sorted(unmatched),
        "event_types_in_scope": sorted(str(t["event_type"]) for t in in_scope),
    }
    if privileged_patterns:
        scope.update(summarize(in_scope, scoped=True))
        # Same guard as the sibling fetchers', with the extra condition this
        # scope needs: a pattern set that matched nothing produces an empty
        # scope, over which every positive is vacuously true. `unmatched` being
        # non-empty does not fail the scope on its own — a deployment may
        # legitimately never have run one of the named commands — but a scope
        # with no events in it at all is not assessable.
        scope["scope_is_assessable"] = bool(
            privileged_patterns and in_scope and scope["events_observed"] > 0
        )
        scope["all_assessed_elements_fully_covered"] = (
            bool(scope["all_assessed_elements_fully_covered"]) and scope["scope_is_assessable"]
        )
        scope["command_text_max_length"] = max(
            (t["command_text_max_length"] or 0 for t in in_scope), default=0
        )
        scope["event_types_carrying_command_text"] = sorted(
            str(t["event_type"])
            for t in in_scope
            if t["elements"]["privileged_command_text"]["events_covered"] > 0
        )
    else:
        scope["scope_is_assessable"] = False

    return {
        "authenticated_as": caller,
        "server": server,
        "search": {
            "endpoint": "POST /services/search/jobs",
            "exec_mode": "oneshot",
            "spl": spl,
            "earliest_time": window,
            "latest_time": "now",
            "max_time_secs": timeout_secs,
            "result_rows": len(rows),
            "messages": messages,
        },
        "search_api_note": (
            "The search runs as a SINGLE synchronous call: POST "
            "/services/search/jobs with exec_mode=oneshot, which executes the "
            "search and returns its rows in the body of the same response. The "
            "response carries no search id, so there is no dispatchState poll "
            "loop and no separate /results/ call. A transient job IS registered "
            "on the deployment and is visible in GET /services/search/jobs until "
            "Splunk reaps it on its own ttl; the fetcher cannot delete it "
            "explicitly, because a oneshot response never returns the sid, and "
            "does not need to, since the jobs do not accumulate. "
            "output_mode=json is set on that call because that call is the one "
            "returning the rows — Splunk's search results are XML by default, "
            "and setting the parameter only when creating an asynchronous job "
            "is the standard way to end up parsing XML as JSON. The search is "
            "bounded twice, by Splunk's own max_time server-side and by the HTTP "
            "read timeout client-side, so neither a runaway search nor a stalled "
            "socket can block the run; a search that hits either bound is "
            "reported as a diagnosed timeout and never as an empty result set."
        ),
        "measurement_note": (
            "Every element is measured from NAMED Splunk fields, listed per "
            "element in `read_from_fields`, and no element is reported as "
            "covered without naming the field the coverage was read from. Each "
            "field is counted TWICE: `events_with_field_present` (the field "
            "exists and is non-empty) and `events_with_meaningful_value` (it "
            "also holds something other than a placeholder such as the literal "
            f"{sorted(PLACEHOLDER_VALUES)}). The distinction is load-bearing "
            "rather than pedantic: Splunk writes `n/a` into `user` on audit "
            "records that had no principal, so a fetcher counting presence alone "
            "would report that every record carries an associated identity while "
            "most of them identify nobody. Elements whose meaning depends on the "
            "value — identity, source, outcome, event type — are scored on the "
            "meaningful count; `when` is scored on presence, since a timestamp's "
            "value is not a placeholder question."
        ),
        "self_observation_note": (
            "Splunk audits searches, so running this fetcher writes records into "
            "the index it measures, and the search this fetcher runs appears in "
            "its own results — typically as `action=search` with "
            "`info=\"granted REST: /search/jobs\"`, alongside the `login "
            "attempt` its authentication produced. Those records are NOT "
            "filtered out. Excluding them would mean editing the evidence to "
            "flatter it, and on a quiet deployment they may be a visible share "
            "of the traffic, which a reader should be able to see rather than "
            "have silently removed."
        ),
        "evidence_boundary": {
            "proves": [
                "which event types were actually written to the named audit indexes over the window, and at what volume",
                "the real first and last event timestamps observed, which may be a far shorter span than the window requested",
                "per event type, what fraction of its records carry each named non-repudiation field",
                "that identities recorded are real principals rather than placeholders, counted separately from field presence",
                "the distinct outcome values observed, so the outcome field can be seen to record failure as well as success",
                "that the full text of privileged commands is captured, from the count and character length of the text field",
            ],
            "does_not_prove": [
                "that the event types observed are the ones that OUGHT to be logged — this records what is there, not what is missing from the logging policy",
                "that a component which never emitted an event during the window is not logging; absence over a window is not absence of capability",
                "that the audit records are protected from modification, or that anyone reviews them",
                "that the values recorded are accurate, only that the fields are populated",
                "anything about sources that do not forward into these indexes at all — see the splunk_data_inputs fetcher for what is configured to ship",
            ],
        },
        "event_types": event_types,
        "summary": summary,
        "privileged_command_scope": scope,
        "api_failures": api_failures,
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Interim v0.x: fetcher loads .env itself. The framework's runner +
    # secret resolver will pass resolved values in and this block goes away.
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)

    host = os.environ.get("SPLUNK_HOST", "")
    token = os.environ.get("SPLUNK_TOKEN", "")
    username = os.environ.get("SPLUNK_USERNAME", "")
    password = os.environ.get("SPLUNK_PASSWORD", "")
    target_name = os.environ.get("SPLUNK_TARGET_NAME", "") or host
    verify_ssl = env_flag("SPLUNK_VERIFY_SSL", True)

    if not host:
        report_failure("Missing required env var: SPLUNK_HOST", "bad_config")
        return 1
    if not token and not (username and password):
        report_failure(
            "No Splunk credential: supply SPLUNK_TOKEN, or SPLUNK_USERNAME and SPLUNK_PASSWORD",
            "bad_config",
        )
        return 1

    # `_audit` is Splunk's own fixed-name audit index, present under that exact
    # name on every deployment, so falling back to it is a platform fact rather
    # than a guess about this installation.
    indexes = csv_env("SPLUNK_AUDIT_INDEXES") or [DEFAULT_AUDIT_INDEX]
    privileged_patterns = csv_env("SPLUNK_PRIVILEGED_EVENT_TYPES")
    window = os.environ.get("SPLUNK_AUDIT_SEARCH_WINDOW", "").strip() or "-7d"
    timeout_secs = int_env("SPLUNK_AUDIT_SEARCH_TIMEOUT_SECS", 300)
    include_samples = env_flag("SPLUNK_INCLUDE_COMMAND_SAMPLES", False)

    if not verify_ssl:
        # Only reachable when the target explicitly opted out, which the schema
        # restricts to sandboxes. Suppressing the warning keeps it off stderr,
        # whose tail the runner reads as the failure reason. Filtered by message
        # rather than by class so this stays stdlib-only and urllib3 need not be
        # imported (or declared) just to name an exception type.
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    session = build_session(token, username, password, verify_ssl)
    auth_method = "bearer_token" if token else "basic_auth"

    failure: Dict[str, str] = {}
    try:
        result = collect(
            session, host, indexes, privileged_patterns, window, timeout_secs, include_samples
        )
    except PermissionError as exc:
        result = {"api_failures": [{"operation": "collect", "type": "PermissionError", "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "not_authorized"}
    except TimeoutError as exc:
        result = {"api_failures": [{"operation": "search", "type": "TimeoutError", "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "timeout"}
    except requests.exceptions.RequestException as exc:
        result = {"api_failures": [{"operation": "collect", "type": type(exc).__name__, "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "target_unreachable"}
    except Exception as exc:
        result = {"api_failures": [{"operation": "collect", "type": type(exc).__name__, "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "internal_error"}

    api_failures = result.get("api_failures", [])
    evidence = {
        "target_name": target_name,
        "splunk_host": host,
        "auth_method": auth_method,
        "tls_verified": verify_ssl,
        "collected_at": current_timestamp(),
        "partial_failure": bool(api_failures) and not failure,
        **result,
    }

    output_path = output_dir / f"splunk_audit_event_types_{sanitize_for_filename(target_name)}.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)
    # Reported AFTER the success line above: the runner reads the TAIL of stderr
    # as the failure reason, so whichever line is logged last wins. report_failure
    # does the error-level logging itself — logging the reason here as well puts
    # it on stderr twice (tests/test_failure_reporting_contract.py enforces this).
    if failure:
        report_failure(failure["reason"], failure["code"])
        return 1
    if api_failures:
        report_failure(
            "; ".join(f"{f['operation']}: {f['message']}" for f in api_failures),
            "partial_failure",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
