#!/usr/bin/env python3
"""
Splunk Data Inputs and Log Ingest Coverage

The INGEST side of an audit-logging claim: which components actually ship logs
into Splunk. splunk_audit_event_types proves what arrived; this proves what is
configured to send, and — where splunkd can tell us — what is actually connected.

Three distinctions carry the whole file, because collapsing any of them turns a
finding into a false pass:

  CONFIGURED vs ENABLED      a disabled input is configured and sends nothing.
  PRESENT vs MEANINGFUL      `index: "default"` names no destination and
                             `host: "$decideOnStartup"` identifies no component,
                             yet both fields are present on every input. This is
                             the same trap splunk_audit_event_types hit, where
                             `user` was present on 100% of audit records and
                             held a real principal on 13.5%.
  LOCAL vs REMOTE            a deployment whose only live inputs are its own
                             local files is not "log management on all
                             production components".

Two endpoint facts, measured on a live deployment, that a fetcher reading only
the obvious path gets wrong:

  * `/services/data/inputs/all` does NOT cover the HTTP Event Collector. The
    `http` kind appears nowhere in its entries, and the HEC global stanza lives
    at the singleton path `data/inputs/http/http`, not in any collection. Read
    only `all` and a deployment with HEC wide open reports as having no HEC.
  * `/services/data/inputs/tcp/cooked/<port>/connections` returns a live census
    of the forwarders currently connected to the receiving port — the strongest
    search-free answer to "do remote components actually ship logs". It is a
    snapshot, not history, and is reported as such.
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

logger = logging.getLogger("splunk_data_inputs")

# Values Splunk writes where a real one would go. `default` is the literal
# string splunkd stores when no index is named — it is not a destination, and
# counting it as one is the difference between "69 inputs feed our audit index"
# and the truth.
INDEX_PLACEHOLDERS = {"", "default", "null", "none"}
HOST_PLACEHOLDERS = {"", "$decideOnStartup", "$decideonstartup"}

# Splunk's own apps. Annotation only — no verdict depends on this list, so
# widening it cannot green-wash anything. See `vendor_input_apps` in fetcher.yaml.
DEFAULT_VENDOR_APPS = (
    "system,learned,search,splunk_*,Splunk*,introspection_generator_addon,"
    "python_upgrade_readiness_app,journald_input,legacy,alert_*,sample_app,"
    "appsbrowser,dmc,framework"
)

# Keys whose VALUE must never reach the evidence file. Matched on the key name,
# so an unfamiliar credential-shaped field on a future input type is caught by
# shape rather than by enumeration.
CREDENTIAL_KEY = re.compile(
    r"token|password|passwd|secret|credential|apikey|api_key|privatekey|private_key",
    re.IGNORECASE,
)

# Everything the evidence records about an input, by explicit allowlist. The raw
# content block is NEVER copied wholesale: that is what keeps a credential on an
# input type nobody anticipated out of the file.
CONTENT_FIELDS = (
    "index", "sourcetype", "host", "source", "disabled", "interval",
    "queue", "eai:type", "eai:location",
)


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


def env_list(name: str, default: str = "") -> List[str]:
    return [v.strip() for v in os.environ.get(name, default).split(",") if v.strip()]


def build_session(token: str, username: str, password: str, verify_ssl: bool) -> requests.Session:
    """Bearer token if we have one, HTTP basic otherwise."""
    session = requests.Session()
    session.verify = verify_ssl
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    else:
        session.auth = (username, password)
    return session


def get_json(session: requests.Session, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    merged = {"output_mode": "json", **params}
    response = session.get(url, params=merged, timeout=60)
    if response.status_code in (401, 403):
        raise PermissionError(f"{response.status_code} from {url}: {response.text[:300]}")
    if response.status_code != 200:
        raise RuntimeError(f"{response.status_code} from {url}: {response.text[:300]}")
    return response.json()


def to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def matches_any(name: str, patterns: List[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def meaningful_index(raw: Any) -> Optional[str]:
    """The index this input actually names, or None if it names none."""
    if not isinstance(raw, str):
        return None
    return None if raw.strip().lower() in INDEX_PLACEHOLDERS else raw.strip()


def meaningful_host(raw: Any) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    return None if raw.strip() in HOST_PLACEHOLDERS or raw.strip() == "" else raw.strip()


def describe_input(entry: Dict[str, Any], vendor_apps: List[str]) -> Dict[str, Any]:
    content = entry.get("content", {}) or {}
    acl = entry.get("acl", {}) or {}

    index_raw = content.get("index")
    host_raw = content.get("host")
    index_named = meaningful_index(index_raw)
    host_named = meaningful_host(host_raw)
    app = acl.get("app")

    # Recorded by NAME, never by value — see CREDENTIAL_KEY.
    credential_fields = sorted(k for k in content if CREDENTIAL_KEY.search(k))

    record = {
        "name": entry.get("name"),
        "kind": content.get("eai:type"),
        "app": app,
        "owner": acl.get("owner"),
        "sharing": acl.get("sharing"),
        "disabled": bool(content.get("disabled", False)),
        "enabled": not bool(content.get("disabled", False)),
        # present vs meaningful, both surfaced: the gap between them IS the finding
        "index_field_present": index_raw is not None,
        "index_raw": index_raw,
        "index_named": index_named,
        "targets_a_named_index": index_named is not None,
        "host_field_present": host_raw is not None,
        "host_raw": host_raw,
        "host_named": host_named,
        "identifies_a_host": host_named is not None,
        "is_vendor_app": bool(app) and matches_any(str(app), vendor_apps),
        "credential_fields_present": credential_fields,
    }
    for field in ("sourcetype", "source", "interval", "queue", "eai:location"):
        record[field.replace("eai:", "eai_")] = content.get(field)
    return record


def summarize(inputs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Roll-up over whichever set of inputs is handed in.

    Every verdict here is a POSITIVE assertion, and a positive over an empty set
    is vacuously true — "every input targets a named index" holds when there are
    no inputs. So each verdict is AND-ed with `bool(inputs)` locally, and the
    caller AND-s in the scope-level guard as well.
    """
    enabled = [i for i in inputs if i["enabled"]]
    named = [i for i in enabled if i["targets_a_named_index"]]
    return {
        "inputs_configured": len(inputs),
        "inputs_enabled": len(enabled),
        "inputs_disabled": len(inputs) - len(enabled),
        "inputs_enabled_targeting_a_named_index": len(named),
        "inputs_with_index_field_present": sum(1 for i in inputs if i["index_field_present"]),
        "inputs_identifying_a_host": sum(1 for i in enabled if i["identifies_a_host"]),
        "customer_authored_inputs": sum(1 for i in inputs if not i["is_vendor_app"]),
        "vendor_inputs": sum(1 for i in inputs if i["is_vendor_app"]),
        "distinct_indexes_targeted": sorted({i["index_named"] for i in named}),
        "any_input_enabled": bool(inputs) and len(enabled) > 0,
        "every_enabled_input_targets_a_named_index": (
            bool(inputs) and len(enabled) > 0 and len(named) == len(enabled)
        ),
    }


def collect(
    session: requests.Session,
    host: str,
    audit_indexes: List[str],
    vendor_apps: List[str],
) -> Dict[str, Any]:
    base = host.rstrip("/")
    api_failures: List[Dict[str, str]] = []

    def optional(operation: str, path: str, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """For context calls whose absence must not fail the whole collection.

        A 404 here is a real answer — several input paths simply do not exist on
        a given Splunk build — so it is recorded as absent rather than as a
        failure. Anything else is a failure worth reporting.
        """
        try:
            return get_json(session, f"{base}{path}", params)
        except PermissionError:
            raise
        except RuntimeError as exc:
            if "404" in str(exc):
                return None
            api_failures.append({"operation": operation, "type": "RuntimeError", "message": str(exc)})
            return None
        except Exception as exc:
            api_failures.append({"operation": operation, "type": type(exc).__name__, "message": str(exc)})
            return None

    server: Dict[str, Any] = {}
    info = optional("GET /services/server/info", "/services/server/info", {})
    if info:
        c = (info.get("entry") or [{}])[0].get("content", {})
        server = {
            "version": c.get("version"),
            "product_type": c.get("product_type"),
            "server_name": c.get("serverName"),
        }

    authenticated_as = None
    ctx = optional(
        "GET /services/authentication/current-context",
        "/services/authentication/current-context",
        {"count": 0},
    )
    if ctx:
        cc = (ctx.get("entry") or [{}])[0].get("content", {})
        authenticated_as = {"username": cc.get("username"), "roles": cc.get("roles")}

    # The inventory. This one is NOT optional — it is the evidence.
    data = get_json(session, f"{base}/services/data/inputs/all", {"count": 0})
    inputs = [describe_input(e, vendor_apps) for e in (data.get("entry") or [])]

    # HEC lives outside /data/inputs/all entirely. Measured, not assumed.
    hec_tokens = optional("GET /services/data/inputs/http", "/services/data/inputs/http", {"count": 0})
    hec_global = optional(
        "GET /services/data/inputs/http/http", "/services/data/inputs/http/http", {"count": 0}
    )
    hec_global_content = ((hec_global or {}).get("entry") or [{}])[0].get("content", {})
    hec = {
        "endpoint_covered_by_inputs_all": False,
        "global_stanza_present": hec_global is not None,
        "global_enabled": (
            not bool(hec_global_content.get("disabled", True)) if hec_global else None
        ),
        "port": hec_global_content.get("port") if hec_global else None,
        "token_count": len((hec_tokens or {}).get("entry") or []) if hec_tokens else 0,
        # Tokens are recorded by name and enabled-state ONLY. Never by value.
        "tokens": [
            {
                "name": e.get("name"),
                "index": (e.get("content", {}) or {}).get("index"),
                "enabled": not bool((e.get("content", {}) or {}).get("disabled", False)),
            }
            for e in ((hec_tokens or {}).get("entry") or [])
        ],
    }

    # Remote ingest: is anything actually connected, right now?
    receiving_ports: List[Dict[str, Any]] = []
    cooked = optional(
        "GET /services/data/inputs/tcp/cooked", "/services/data/inputs/tcp/cooked", {"count": 0}
    )
    for entry in (cooked or {}).get("entry") or []:
        port = entry.get("name")
        conns = optional(
            f"GET /services/data/inputs/tcp/cooked/{port}/connections",
            f"/services/data/inputs/tcp/cooked/{port}/connections",
            {"count": 0},
        )
        receiving_ports.append({
            "port": port,
            "enabled": not bool((entry.get("content", {}) or {}).get("disabled", False)),
            "connected_forwarders": len((conns or {}).get("entry") or []) if conns else 0,
        })

    ds_clients = optional(
        "GET /services/deployment/server/clients", "/services/deployment/server/clients", {"count": 0}
    )
    connected_now = sum(p["connected_forwarders"] for p in receiving_ports)
    remote_ingest = {
        "receiving_ports": receiving_ports,
        "receiving_enabled": any(p["enabled"] for p in receiving_ports),
        "connected_forwarders_now": connected_now,
        "deployment_server_clients": len((ds_clients or {}).get("entry") or []) if ds_clients else 0,
        "any_remote_component_ships_logs": connected_now > 0,
        "measurement_note": (
            "connected_forwarders_now is a LIVE SNAPSHOT of forwarders attached to the "
            "receiving port at collection time, not a history. A forwarder that ships "
            "hourly and is between connections reads as absent here. Absence of "
            "connections is therefore weaker evidence than presence of them."
        ),
    }

    summary = summarize(inputs)
    summary["scope_is_assessable"] = bool(inputs)
    for verdict in ("any_input_enabled", "every_enabled_input_targets_a_named_index"):
        summary[verdict] = bool(summary[verdict]) and summary["scope_is_assessable"]

    # --- The index-keyed roll-up ------------------------------------------------
    # Keyed on the INDEX, not on the input, because the question this answers is
    # "does anything write to the indexes the audit claim depends on?" An index
    # configured with 365 days of retention that nothing feeds proves nothing,
    # and this is the only fetcher on the slate that can say so.
    scope: Dict[str, Any] = {
        "configured": bool(audit_indexes),
        "indexes_named": sorted(audit_indexes),
    }
    if audit_indexes:
        # Splunk-internal indexes are written by splunkd directly and never have
        # a data input. Scoring them as missing one reports a platform fact as a
        # finding, so they are listed and excluded from assessment.
        internal = sorted(n for n in audit_indexes if n.startswith("_"))
        assessed = sorted(n for n in audit_indexes if not n.startswith("_"))
        per_index = []
        for name in assessed:
            targeting = [i for i in inputs if i["index_named"] == name]
            enabled_targeting = [i for i in targeting if i["enabled"]]
            per_index.append({
                "index": name,
                "inputs_targeting": [i["name"] for i in targeting],
                "inputs_targeting_count": len(targeting),
                "enabled_inputs_targeting_count": len(enabled_targeting),
                "has_enabled_input": len(enabled_targeting) > 0,
            })
        without = [p["index"] for p in per_index if not p["has_enabled_input"]]
        scope.update({
            "indexes_internal_not_assessed": internal,
            "indexes_assessed": assessed,
            "per_index": per_index,
            "indexes_assessed_count": len(assessed),
            "indexes_with_an_enabled_input": len(assessed) - len(without),
            "indexes_without_an_enabled_input": sorted(without),
            "scope_is_assessable": bool(inputs) and len(assessed) > 0,
        })
        scope["every_assessed_audit_index_has_an_enabled_input"] = (
            len(without) == 0 and scope["scope_is_assessable"]
        )
    else:
        scope["scope_is_assessable"] = False
        scope["every_assessed_audit_index_has_an_enabled_input"] = False

    return {
        "server": server,
        "authenticated_as": authenticated_as,
        "inputs": sorted(inputs, key=lambda i: (str(i["kind"]), str(i["name"]))),
        "hec": hec,
        "remote_ingest": remote_ingest,
        "summary": summary,
        "audit_scope": scope,
        "field_semantics_note": (
            "index_named is null where splunkd stores the literal 'default', which names "
            "no destination; host_named is null for '$decideOnStartup'. Both raw values are "
            "kept alongside. A count of inputs whose index FIELD is present is not a count "
            "of inputs that feed a named index, and only the latter bears on the claim."
        ),
        "credential_handling_note": (
            "Input fields are copied by explicit allowlist, never wholesale. Any key whose "
            "name is credential-shaped is recorded in credential_fields_present by NAME "
            "only; no credential value is ever written to this evidence."
        ),
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

    audit_indexes = env_list("SPLUNK_AUDIT_INDEXES")
    vendor_apps = env_list("SPLUNK_VENDOR_INPUT_APPS", DEFAULT_VENDOR_APPS)

    if not verify_ssl:
        # Only reachable when the target explicitly opted out, which the schema
        # restricts to sandboxes. Filtered by message rather than by class so
        # this stays stdlib-only and urllib3 need not be imported.
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    session = build_session(token, username, password, verify_ssl)
    auth_method = "bearer_token" if token else "basic_auth"

    failure: Dict[str, str] = {}
    try:
        result = collect(session, host, audit_indexes, vendor_apps)
    except PermissionError as exc:
        result = {"api_failures": [{"operation": "collect", "type": "PermissionError", "message": str(exc)}]}
        failure = {"reason": str(exc), "code": "not_authorized"}
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

    output_path = output_dir / f"splunk_data_inputs_{sanitize_for_filename(target_name)}.json"
    with open(output_path, "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    logger.info("Evidence saved to %s", output_path)
    # Reported AFTER the success line: the runner reads the TAIL of stderr as the
    # failure reason. report_failure does the error-level logging itself — logging
    # the reason here as well puts it on stderr twice, which
    # tests/test_failure_reporting_contract.py enforces against.
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
