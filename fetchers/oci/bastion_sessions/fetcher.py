#!/usr/bin/env python3
"""
OCI Bastion — time-boxed administrative access, and the sessions opened through it

Every Bastion in scope with the three settings that decide whether it is
genuinely just-in-time access — the maximum session lifetime, the maximum number
of concurrent sessions, and the CIDR allow-list of who may connect at all —
plus every session recorded against it.

This is the evidence for KSI-IAM-JIT, "a least-privileged, role and
attribute-based, and just-in-time security authorization model is used and
persistently reviewed for all user and non-user accounts and services". A
Bastion is OCI's answer to standing SSH access: hosts sit in a private subnet
with no public IP, and an operator opens a session that expires on its own.

WHAT MAKES THIS EVIDENCE RATHER THAN AN INVENTORY: a bastion configured with the
maximum TTL and an allow-list of 0.0.0.0/0 is a permanently-reachable jump host
wearing the word "bastion". The two fields that separate those cases are
`max_session_ttl_in_seconds` and `client_cidr_block_allow_list`, so both are
read per bastion and both are judged in the summary.

AN N+1 THAT IS NOT AN OVERSIGHT: `list_bastions` returns BastionSummary, which
does NOT carry `max_session_ttl_in_seconds`, `max_sessions_allowed` or
`client_cidr_block_allow_list` — verified against a live bastion, where the
summary model simply has no such attributes. Every field this fetcher exists to
report is only on the full `get_bastion` response, so one detail call per
bastion is mandatory rather than lazy. Bastion counts are small (they are
per-subnet infrastructure, not per-workload), so this stays bounded.
"""

import ipaddress
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from oci_common import (  # noqa: E402
    Collector,
    age_in_days,
    as_bool,
    build_payload,
    coverage_percentage,
    finish,
    iso,
    list_all,
    load_config,
    make_client,
    resolve_scope,
    sanitize_for_filename,
    service_not_subscribed,
    short_ocid,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_bastion_sessions")

# "The whole internet", in both address families. An allow-list containing
# either is not an allow-list.
INTERNET_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

# OCI's own maximum, and its default, for a bastion session. A bastion left at
# the maximum has taken the loosest setting the service offers, which is worth
# reporting even though it is legal.
MAX_SESSION_TTL_SECONDS = 10800  # 3 hours

# Above this, a "temporary" session lasts most of a working day. Deliberately a
# fixed, documented threshold rather than a config knob, so the evidence means
# the same thing in every tenancy.
LONG_SESSION_TTL_SECONDS = 3600  # 1 hour

# Sessions in these states can still carry live access.
ACTIVE_SESSION_STATES = frozenset({"ACTIVE", "CREATING"})


# --- pure transforms ---

def allows_internet(cidrs) -> bool:
    """True when the allow-list admits the whole internet, or is absent entirely.

    An EMPTY or missing allow-list is the permissive case, not the restrictive
    one: OCI treats "no allow-list" as "no client CIDR restriction". Reading
    empty as locked-down would invert the finding, which is the kind of mistake
    that makes a compliance report worse than none.

    Judged on the addresses, not the spelling: the entries are collapsed per
    address family, so `0.0.0.0/1` + `128.0.0.0/1`, or `0::/0`, admit the whole
    internet exactly as `0.0.0.0/0` does. An entry that does not parse is kept
    as a literal and matched by string, so it can never read as restrictive by
    being skipped.
    """
    if not cidrs:
        return True
    networks = []
    for cidr in cidrs:
        text = str(cidr).strip()
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            if text in INTERNET_CIDRS:
                return True
    v4 = [n for n in networks if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in networks if isinstance(n, ipaddress.IPv6Network)]
    return (any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(v4))
            or any(n.prefixlen == 0 for n in ipaddress.collapse_addresses(v6)))


def bastion_record(bastion: dict, *, now=None) -> dict:
    """Normalize one bastion into an evidence record."""
    ttl = bastion.get("max_session_ttl_in_seconds")
    allow_list = bastion.get("client_cidr_block_allow_list") or []
    open_to_internet = allows_internet(allow_list)

    return {
        "id": bastion.get("id"),
        "name": bastion.get("name"),
        "compartment_id": bastion.get("compartment_id"),
        "bastion_type": bastion.get("bastion_type"),
        "lifecycle_state": bastion.get("lifecycle_state"),
        "lifecycle_details": bastion.get("lifecycle_details"),
        "target_vcn_id": bastion.get("target_vcn_id"),
        "target_subnet_id": bastion.get("target_subnet_id"),
        "private_endpoint_ip_address": bastion.get("private_endpoint_ip_address"),
        # The JIT settings. None means the detail call failed, not "unlimited" —
        # the summary counts those separately so a failed read never reads clean.
        "max_session_ttl_in_seconds": ttl,
        "max_sessions_allowed": bastion.get("max_sessions_allowed"),
        "client_cidr_block_allow_list": sorted(str(c) for c in allow_list),
        "client_cidr_restricted": not open_to_internet,
        "client_cidr_allows_internet": open_to_internet,
        # Sitting at OCI's ceiling is legal but is the loosest available setting.
        "at_maximum_session_ttl": ttl == MAX_SESSION_TTL_SECONDS if ttl is not None else None,
        "session_ttl_over_one_hour": ttl > LONG_SESSION_TTL_SECONDS if ttl is not None else None,
        # A static jump host is standing access, which is the opposite of JIT.
        "static_jump_hosts": sorted(bastion.get("static_jump_host_ip_addresses") or []),
        "has_static_jump_hosts": bool(bastion.get("static_jump_host_ip_addresses")),
        "dns_proxy_status": bastion.get("dns_proxy_status"),
        "time_created": iso(bastion.get("time_created")),
        "time_updated": iso(bastion.get("time_updated")),
        # True only when the detail call succeeded — see the module docstring.
        "detail_read": ttl is not None,
    }


def session_record(session: dict, *, bastion_id=None, now=None) -> dict:
    """Normalize one bastion session.

    Target details arrive as one of several polymorphic subtypes keyed on
    `session_type`; the fields read here are the ones common to the managed-SSH
    and port-forwarding shapes, so an unrecognised subtype degrades to nulls
    rather than raising.
    """
    target = session.get("target_resource_details") or {}
    state = session.get("lifecycle_state")
    ttl = session.get("session_ttl_in_seconds")

    return {
        "id": session.get("id"),
        "display_name": session.get("display_name"),
        "bastion_id": session.get("bastion_id") or bastion_id,
        "bastion_name": session.get("bastion_name"),
        "lifecycle_state": state,
        "lifecycle_details": session.get("lifecycle_details"),
        "is_active": state in ACTIVE_SESSION_STATES,
        "session_ttl_in_seconds": ttl,
        "session_ttl_over_one_hour": ttl > LONG_SESSION_TTL_SECONDS if ttl is not None else None,
        "session_type": target.get("session_type"),
        "target_resource_id": target.get("target_resource_id"),
        "target_resource_display_name": target.get("target_resource_display_name"),
        "target_resource_private_ip_address": target.get("target_resource_private_ip_address"),
        "target_resource_port": target.get("target_resource_port"),
        # Which OS account the operator assumed — the least-privilege half of
        # the indicator. Only managed-SSH sessions carry it.
        "target_os_username": target.get("target_resource_operating_system_user_name"),
        "time_created": iso(session.get("time_created")),
        "time_updated": iso(session.get("time_updated")),
        "days_since_created": age_in_days(session.get("time_created"), now=now),
    }


def summarize(bastions: list[dict], sessions: list[dict], *, api_readable: bool = True) -> dict:
    """Aggregate into the just-in-time question an assessor asks first."""
    read = [b for b in bastions if b["detail_read"]]
    restricted = [b for b in read if b["client_cidr_restricted"]]
    ttls = [b["max_session_ttl_in_seconds"] for b in read if b["max_session_ttl_in_seconds"]]
    active = [s for s in sessions if s["is_active"]]

    return {
        # False when Bastion is not subscribed (recorded in
        # metadata.skipped_calls) or the list call failed — not "no bastions".
        "bastion_service_readable": api_readable,
        "total_bastions": len(bastions),
        "active_bastions": sum(1 for b in bastions if b["lifecycle_state"] == "ACTIVE"),
        # Non-zero means some JIT settings below could not be read at all, so
        # the percentages are over a smaller denominator than total_bastions.
        "bastions_with_unreadable_detail": len(bastions) - len(read),
        # The two findings.
        "bastions_with_cidr_allow_list": len(restricted),
        "bastions_open_to_any_client_ip": sum(1 for b in read if b["client_cidr_allows_internet"]),
        "cidr_restriction_percentage": coverage_percentage(len(restricted), len(read)),
        "bastions_at_maximum_session_ttl": sum(1 for b in read if b["at_maximum_session_ttl"]),
        "bastions_with_session_ttl_over_one_hour": sum(
            1 for b in read if b["session_ttl_over_one_hour"]
        ),
        "bastions_with_static_jump_hosts": sum(1 for b in bastions if b["has_static_jump_hosts"]),
        "shortest_max_session_ttl_seconds": min(ttls) if ttls else None,
        "longest_max_session_ttl_seconds": max(ttls) if ttls else None,
        # Sessions. An empty list is the expected state for a tenancy where
        # nobody is currently connected, and is not evidence of a problem.
        "total_sessions": len(sessions),
        "active_sessions": len(active),
        "sessions_by_type": sorted({s["session_type"] for s in sessions if s["session_type"]}),
        "distinct_session_targets": len(
            {s["target_resource_id"] for s in sessions if s["target_resource_id"]}
        ),
        "os_usernames_assumed": sorted(
            {s["target_os_username"] for s in sessions if s["target_os_username"]}
        ),
        "bastion_names": sorted(f"{b['name']} ({short_ocid(b['id'])})" for b in bastions if b["name"]),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool):
    """Bastions (with detail) and their sessions across every compartment in scope."""
    import oci  # lazy

    identity = make_client(oci.identity.IdentityClient, auth)
    bastion_client = make_client(oci.bastion.BastionClient, auth)

    compartments = walk_compartments(
        identity,
        scope["compartment_id"],
        collector,
        include_subcompartments=include_sub,
        tenancy=auth.get("tenancy"),
    )

    bastions: list[dict] = []
    sessions: list[dict] = []
    unreadable = 0

    for comp in compartments:
        cid, cname = comp["id"], comp["name"]

        found = collector.guard(
            f"bastion.list_bastions ({cname})",
            lambda c=cid: list_all(bastion_client.list_bastions, c),
            tolerate=service_not_subscribed,
        )
        if found is None:
            unreadable += 1
            continue

        for summary in found:
            # Mandatory second call: the summary carries none of the JIT fields.
            detail = collector.guard(
                f"bastion.get_bastion ({short_ocid(summary.id)})",
                lambda b=summary.id: bastion_client.get_bastion(b).data,
            )
            # Fall back to the summary so a bastion is never silently absent
            # from the inventory just because its detail call failed;
            # `detail_read` marks it and the summary counts it.
            bastions.append(bastion_record(to_plain(detail if detail is not None else summary)))

            for session in collector.guard(
                f"bastion.list_sessions ({short_ocid(summary.id)})",
                lambda b=summary.id: list_all(bastion_client.list_sessions, b),
                default=[],
            ) or []:
                sessions.append(session_record(to_plain(session), bastion_id=summary.id))

    if compartments and unreadable == len(compartments):
        return None, None, len(compartments)

    bastions.sort(key=lambda r: (r.get("name") or "", r.get("id") or ""))
    sessions.sort(key=lambda r: (r.get("time_created") or "", r.get("id") or ""), reverse=True)
    return bastions, sessions, len(compartments)


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    load_dotenv()

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    collector = Collector(logger)
    include_sub = as_bool(os.environ.get("OCI_INCLUDE_SUBCOMPARTMENTS"), default=True)

    auth: dict = {}
    scope: dict = {"compartment_id": None, "compartment_source": "unresolved"}
    bastions = sessions = None
    scanned = None

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            # Guarded as a whole: building a client parses the signing key, so a
            # malformed OCI_PRIVATE_KEY raises here rather than inside a guard.
            try:
                bastions, sessions, scanned = collect(
                    auth, scope, collector, include_sub=include_sub
                )
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("bastion.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={"bastions": bastions or [], "sessions": sessions or []},
        summary=summarize(bastions or [], sessions or [], api_readable=bastions is not None),
        compartments_scanned=scanned,
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_bastion_sessions_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)

    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
