#!/usr/bin/env python3
"""
OCI Zero Trust Packet Routing — network intent written as policy, and how loose it is

Whether ZPR is enabled for the tenancy, every ZPR policy in scope with each
statement parsed into source, destination and conditions, the security
attribute namespaces and definitions those statements can reference, and which
VCNs carry a ZPR attribute or run ZPR-only.

This is the evidence for KSI-CNA-ULN, "logical networking and related
capabilities are used and persistently reviewed to enforce traffic flow
controls", and KSI-CNA-RNT, "resources are persistently reviewed to ensure they
are appropriately configured to limit inbound and outbound network traffic". ZPR
is OCI-only: access is granted between labelled workloads rather than between
IP ranges, so it survives a re-address, and a packet no statement allows is
dropped even when a security list would have let it through.

WHAT MAKES THIS EVIDENCE RATHER THAN AN INVENTORY: a ZPR policy is free text, so
"has ZPR policies" says nothing about what they allow. Every statement is parsed
and the four permissive shapes are counted, each of which Oracle accepts without
complaint (verified by creating them on a live tenancy):

    allow '0.0.0.0/0' to connect to ...            the internet as a source
    allow all-endpoints to connect to ...          anything, inside or out
    ... to connect to '0.0.0.0/0' / all-endpoints   unrestricted egress
    (no `with protocol=` clause)                    every protocol and port

DANGLING REFERENCES ARE ACCEPTED TOO. A policy naming `ns.key:value` goes ACTIVE
even when no namespace `ns` exists — four policies went ACTIVE on the test
tenancy minutes before their namespace was created. A statement whose attribute
is undefined or retired matches nothing; it reads as a control and grants or
blocks nothing. Counted as `statements_with_undefined_attributes`.

THE PARSER IS DELIBERATELY CONSERVATIVE. Oracle documents the grammar only in
prose, so a statement that does not match the documented shapes is kept verbatim
with `parsed: false` and counted, never guessed at. An unparsed statement is
never counted as restrictive.

NOT ENABLED READS AS A 404, NOT A STATUS. Unlike Cloud Guard, which answers
DISABLED, ZPR's `get_configuration` 404s until ZPR has been turned on — and 404
is also OCI's answer to a missing permission. So a 404 is recorded as
`zpr_enabled: false` (the pessimistic reading) with the call in skipped_calls;
if policies are then found anyway, the 404 was a permission problem and is
recorded as a collection failure instead.

TWO FIELDS THAT LOOK USEFUL AND ARE NOT, both verified live:
  * `Instance.security_attributes` is `{}` for an instance whose VNIC carries a
    ZPR attribute — the label lives on the VNIC. This fetcher does not claim
    per-instance coverage for that reason.
  * `Vcn.is_zpr_only` is None, not False, on a VCN that never set it; only True
    is read as ZPR-only.
"""

import logging
import os
import re
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from oci_common import (  # noqa: E402
    Collector,
    as_bool,
    build_payload,
    coverage_percentage,
    finish,
    iso,
    list_all,
    load_config,
    make_client,
    not_found_or_not_subscribed,
    resolve_scope,
    sanitize_for_filename,
    short_ocid,
    to_plain,
    walk_compartments,
    write_evidence,
)

logger = logging.getLogger("oci_zpr_policies")

DEFAULT_NAMESPACE = "oracle-zpr"
INTERNET_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
ANY_ENDPOINT = "all-endpoints"
OCI_SERVICES = "osn-services-ip-addresses"

# Same-VCN:  in <attr> VCN allow <src> to connect to <dst> [with <conditions>]
# Two-VCN:   allow <src> in <attr> VCN to connect to <dst> in <attr> VCN [with ...]
_STATEMENT = re.compile(
    r"^(?:in\s+(?P<vcn>.+?)\s+vcn\s+)?"
    r"allow\s+(?P<src>.+?)(?:\s+in\s+(?P<src_vcn>.+?)\s+vcn)?"
    r"\s+to\s+connect\s+to\s+"
    r"(?P<dst>.+?)(?:\s+in\s+(?P<dst_vcn>.+?)\s+vcn)?"
    r"(?:\s+with\s+(?P<conditions>.+))?$",
    re.IGNORECASE,
)
_CIDR = re.compile(r"^[0-9a-fA-F:.]+/\d{1,3}$")
_ATTRIBUTE = re.compile(r"^(?:(?P<ns>[^.\s:']+)\.)?(?P<key>[^.\s:']+):(?P<value>.+)$")


# --- pure transforms ---

def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    return text


def parse_attribute(text):
    """`ns.key:value` (namespace defaults to oracle-zpr), or None."""
    if text is None:
        return None
    match = _ATTRIBUTE.match(_unquote(text))
    if not match:
        return None
    return {
        "namespace": match["ns"] or DEFAULT_NAMESPACE,
        "key": match["key"],
        "value": match["value"],
    }


def parse_endpoint(text: str) -> dict:
    """Classify one side of a statement."""
    raw = text.strip()
    bare = re.sub(r"\s+endpoints$", "", raw, flags=re.IGNORECASE)
    inner = _unquote(bare)
    if inner.lower() == ANY_ENDPOINT:
        return {"kind": "any", "raw": raw}
    if inner.lower() == OCI_SERVICES:
        return {"kind": "oci_services", "raw": raw}
    if _CIDR.match(inner):
        return {"kind": "internet" if inner in INTERNET_CIDRS else "cidr", "cidr": inner, "raw": raw}
    attribute = parse_attribute(bare)
    if attribute:
        return {"kind": "attribute", "attribute": attribute, "raw": raw}
    return {"kind": "unknown", "raw": raw}


def parse_statement(statement: str) -> dict:
    """One ZPR statement, parsed; unparseable statements are kept, never guessed."""
    text = " ".join(str(statement).split())
    match = _STATEMENT.match(text)
    if not match:
        return {"statement": text, "parsed": False}

    src, dst = parse_endpoint(match["src"]), parse_endpoint(match["dst"])
    conditions = match["conditions"]
    vcns = [parse_attribute(v) for v in (match["vcn"], match["src_vcn"], match["dst_vcn"]) if v]
    attributes = [e["attribute"] for e in (src, dst) if e["kind"] == "attribute"] + [v for v in vcns if v]
    protocol = None
    if conditions:
        found = re.search(r"protocol\s*=\s*'([^']*)'", conditions, re.IGNORECASE)
        protocol = found.group(1) if found else None

    return {
        "statement": text,
        "parsed": src["kind"] != "unknown" and dst["kind"] != "unknown",
        "source": src,
        "destination": dst,
        "conditions": conditions,
        "protocol": protocol,
        "attributes_referenced": attributes,
        "source_is_internet": src["kind"] == "internet",
        "source_is_any_endpoint": src["kind"] == "any",
        "destination_is_internet_or_any": dst["kind"] in ("internet", "any"),
        "protocol_unrestricted": protocol is None,
    }


def policy_record(policy: dict, *, defined=None) -> dict:
    """A ZPR policy with every statement parsed and checked against defined attributes.

    `defined` is the set of (namespace, key) pairs that exist and are not
    retired; None means the definitions could not be read, and then no
    statement is reported as dangling rather than every one.
    """
    statements = []
    for raw in policy.get("statements") or []:
        parsed = parse_statement(raw)
        if parsed["parsed"] and defined is not None:
            parsed["undefined_attributes"] = sorted(
                f"{a['namespace']}.{a['key']}" for a in parsed["attributes_referenced"]
                if (a["namespace"], a["key"]) not in defined
            )
        statements.append(parsed)
    return {
        "id": policy.get("id"),
        "name": policy.get("name"),
        "description": policy.get("description"),
        "compartment_id": policy.get("compartment_id"),
        "lifecycle_state": policy.get("lifecycle_state"),
        "lifecycle_details": policy.get("lifecycle_details"),
        "time_created": iso(policy.get("time_created")),
        "time_updated": iso(policy.get("time_updated")),
        "statements": statements,
    }


def namespace_record(namespace: dict, attributes=None) -> dict:
    return {
        "id": namespace.get("id"),
        "name": namespace.get("name"),
        "compartment_id": namespace.get("compartment_id"),
        "is_retired": namespace.get("is_retired"),
        "lifecycle_state": namespace.get("lifecycle_state"),
        "supported_modes": sorted(namespace.get("mode") or []),
        "attributes": sorted(attributes or []),
    }


def attribute_record(attribute: dict) -> dict:
    return {
        "name": attribute.get("name"),
        "namespace": attribute.get("security_attribute_namespace_name"),
        "type": attribute.get("type"),
        "is_retired": attribute.get("is_retired"),
        "lifecycle_state": attribute.get("lifecycle_state"),
    }


def vcn_record(vcn: dict) -> dict:
    """A VCN's ZPR labels. Attribute values are {namespace: {key: {value, mode}}}."""
    labels = []
    for namespace, keys in sorted((vcn.get("security_attributes") or {}).items()):
        for key, detail in sorted((keys or {}).items()):
            detail = detail if isinstance(detail, dict) else {"value": detail}
            labels.append({
                "namespace": namespace,
                "key": key,
                "value": detail.get("value"),
                "mode": detail.get("mode"),
            })
    return {
        "id": vcn.get("id"),
        "display_name": vcn.get("display_name"),
        "compartment_id": vcn.get("compartment_id"),
        "lifecycle_state": vcn.get("lifecycle_state"),
        "zpr_attributes": labels,
        "in_zpr": bool(labels),
        "zpr_enforced": any(label["mode"] == "enforce" for label in labels),
        # None on a VCN that never set it (verified live); only True is ZPR-only.
        "is_zpr_only": vcn.get("is_zpr_only") is True,
    }


def summarize(configuration, policies, namespaces, vcns, *, definitions_read=True) -> dict:
    statements = [s for p in policies for s in p["statements"]]
    parsed = [s for s in statements if s["parsed"]]
    active = [p for p in policies if p["lifecycle_state"] == "ACTIVE"]
    live_vcns = [v for v in vcns if v["lifecycle_state"] == "AVAILABLE"]
    enforced = [v for v in live_vcns if v["zpr_enforced"]]

    return {
        # None when the configuration read failed outright — unknown, not off.
        "zpr_enabled": configuration["enabled"] if configuration else None,
        "zpr_status": configuration["zpr_status"] if configuration else None,
        "total_policies": len(policies),
        "active_policies": len(active),
        "total_statements": len(statements),
        "unparsed_statements": len(statements) - len(parsed),
        # The four permissive shapes.
        "statements_allowing_internet_source": sum(1 for s in parsed if s["source_is_internet"]),
        "statements_allowing_any_endpoint_source": sum(1 for s in parsed if s["source_is_any_endpoint"]),
        "statements_allowing_internet_or_any_destination": sum(
            1 for s in parsed if s["destination_is_internet_or_any"]
        ),
        "statements_without_protocol_restriction": sum(1 for s in parsed if s["protocol_unrestricted"]),
        # None when attribute definitions could not be read.
        "statements_with_undefined_attributes": sum(
            1 for s in parsed if s.get("undefined_attributes")
        ) if definitions_read else None,
        "security_attribute_namespaces": len(namespaces),
        "security_attribute_definitions": sum(len(n["attributes"]) for n in namespaces),
        # Network coverage.
        "total_vcns": len(live_vcns),
        "vcns_with_zpr_attributes": sum(1 for v in live_vcns if v["in_zpr"]),
        "vcns_with_enforced_zpr": len(enforced),
        "vcns_zpr_only": sum(1 for v in live_vcns if v["is_zpr_only"]),
        "vcn_zpr_enforcement_percentage": coverage_percentage(len(enforced), len(live_vcns)),
        "policy_names": sorted(f"{p['name']} ({short_ocid(p['id'])})" for p in policies if p["name"]),
    }


# --- collection ---

def collect(auth: dict, scope: dict, collector: Collector, *, include_sub: bool) -> dict:
    import oci  # lazy

    tenancy = auth.get("tenancy")
    zpr = make_client(oci.zpr.ZprClient, auth)
    attributes = make_client(oci.security_attribute.SecurityAttributeClient, auth)
    network = make_client(oci.core.VirtualNetworkClient, auth)
    identity = make_client(oci.identity.IdentityClient, auth)
    out: dict = {"configuration": None, "policies": [], "namespaces": [], "vcns": [],
                 "compartments": None, "definitions_read": False}

    config_404 = False

    def read_configuration():
        nonlocal config_404
        try:
            return zpr.get_configuration(compartment_id=tenancy).data
        except Exception as exc:  # noqa: BLE001 — classified below
            if getattr(exc, "status", None) == 404:
                config_404 = True
                collector.skip("zpr.get_configuration", exc)
                return None
            raise

    raw = collector.guard("zpr.get_configuration", read_configuration)
    if raw is not None:
        plain = to_plain(raw)
        out["configuration"] = {"zpr_status": plain.get("zpr_status"),
                                "enabled": plain.get("zpr_status") == "ENABLED",
                                "lifecycle_state": plain.get("lifecycle_state")}
    elif config_404:
        out["configuration"] = {"zpr_status": None, "enabled": False, "lifecycle_state": None}

    # A 404 on the listings is "not enabled" only when the configuration said so
    # too. Tolerated regardless, a collector missing `read zpr-policies` on a
    # tenancy with ZPR ON exited 0 reporting zero policies.
    def zpr_off(exc: BaseException) -> bool:
        return config_404 and not_found_or_not_subscribed(exc)

    # Definitions are tenancy-wide: a statement anywhere may name any of them.
    defined: set = set()
    namespaces = collector.guard(
        "security_attribute.list_security_attribute_namespaces",
        lambda: list_all(attributes.list_security_attribute_namespaces,
                         compartment_id=tenancy, compartment_id_in_subtree=True),
        tolerate=zpr_off,
    )
    if namespaces is not None:
        out["definitions_read"] = True
        for namespace in namespaces:
            ns = to_plain(namespace)
            found = collector.guard(
                f"security_attribute.list_security_attributes ({ns.get('name')})",
                lambda i=ns.get("id"): list_all(attributes.list_security_attributes, i),
            )
            if found is None:
                out["definitions_read"] = False
                found = []
            records = [attribute_record(to_plain(a)) for a in found]
            usable = [r for r in records if not r["is_retired"] and not ns.get("is_retired")]
            defined.update((ns.get("name"), r["name"]) for r in usable)
            out["namespaces"].append(namespace_record(ns, [r["name"] for r in records]))

    compartments = walk_compartments(
        identity, scope["compartment_id"], collector,
        include_subcompartments=include_sub, tenancy=tenancy,
    )
    out["compartments"] = len(compartments)
    for comp in compartments:
        cid, cname = comp["id"], comp["name"]
        for policy in collector.guard(
            f"zpr.list_zpr_policies ({cname})",
            lambda c=cid: list_all(zpr.list_zpr_policies, compartment_id=c),
            default=[], tolerate=zpr_off,
        ) or []:
            out["policies"].append(policy_record(
                to_plain(policy), defined=defined if out["definitions_read"] else None))
        for vcn in collector.guard(
            f"virtual_network.list_vcns ({cname})",
            lambda c=cid: list_all(network.list_vcns, c),
            default=[],
        ) or []:
            out["vcns"].append(vcn_record(to_plain(vcn)))

    # Policies exist but the configuration 404'd: that 404 was a permission gap.
    if config_404 and out["policies"]:
        collector.record(
            "zpr.get_configuration",
            RuntimeError("configuration returned 404 but ZPR policies exist — missing "
                         "`read zpr-configuration` permission, not ZPR disabled"),
        )
        out["configuration"] = None

    out["policies"].sort(key=lambda r: (r.get("name") or "", r.get("id") or ""))
    out["namespaces"].sort(key=lambda r: r.get("name") or "")
    out["vcns"].sort(key=lambda r: (r.get("display_name") or "", r.get("id") or ""))
    return out


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
    collected: dict = {}

    try:
        auth = load_config(collector)
    except Exception as exc:  # noqa: BLE001 — boundary: no credentials is a recorded failure
        collector.record("oci.config.load", exc)

    if auth:
        scope = resolve_scope(auth)
        if scope["compartment_id"]:
            try:
                collected = collect(auth, scope, collector, include_sub=include_sub)
            except Exception as exc:  # noqa: BLE001 — boundary: record, don't crash
                collector.record("zpr.collect", exc)
        else:
            collector.record(
                "resolve_scope",
                RuntimeError("no compartment or tenancy OCID (set OCI_COMPARTMENT_ID or configure auth)"),
            )

    policies = collected.get("policies") or []
    namespaces = collected.get("namespaces") or []
    vcns = collected.get("vcns") or []
    evidence = build_payload(
        auth=auth,
        scope=scope,
        collector=collector,
        results={
            "configuration": collected.get("configuration"),
            "policies": policies,
            "security_attribute_namespaces": namespaces,
            "vcns": vcns,
        },
        summary=summarize(
            collected.get("configuration"), policies, namespaces, vcns,
            definitions_read=collected.get("definitions_read", False),
        ),
        compartments_scanned=collected.get("compartments"),
    )

    target = scope["compartment_id"] or auth.get("tenancy") or "unknown"
    filename = f"oci_zpr_policies_{sanitize_for_filename(target)}.json"
    path = write_evidence(output_dir, filename, evidence)
    return finish(collector, logger, path)


if __name__ == "__main__":
    sys.exit(main())
