"""The ZPR statement parser and the judgments built on it.

Every statement below except the egress and two-VCN shapes was accepted by
Oracle and went ACTIVE on the test tenancy, so these are real grammar, not
guesses at it. The rest come verbatim from Oracle's policy-syntax page.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

FETCHER = Path(__file__).resolve().parent.parent / "fetchers" / "oci" / "zpr_policies" / "fetcher.py"


def _load():
    sys.path.insert(0, str(FETCHER.parent.parent / "_shared"))
    spec = importlib.util.spec_from_file_location("oci_zpr_policies", FETCHER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


zpr = _load()


def test_live_accepted_statements_classify_as_staged():
    tight = zpr.parse_statement(
        "in fetchertest.vcn:test VCN allow fetchertest.role:web endpoints to connect to "
        "fetchertest.role:db endpoints with protocol='tcp/5432'")
    assert tight["parsed"] and tight["protocol"] == "tcp/5432"
    assert not (tight["source_is_internet"] or tight["source_is_any_endpoint"] or tight["protocol_unrestricted"])

    ssh = zpr.parse_statement(
        "in fetchertest.vcn:test VCN allow '0.0.0.0/0' to connect to fetchertest.role:web endpoints "
        "with protocol='tcp/22'")
    assert ssh["source_is_internet"] and not ssh["protocol_unrestricted"]

    anything = zpr.parse_statement(
        "in fetchertest.vcn:test VCN allow all-endpoints to connect to fetchertest.role:db endpoints")
    assert anything["source_is_any_endpoint"] and anything["protocol_unrestricted"]

    osn = zpr.parse_statement(
        "in fetchertest.vcn:test VCN allow fetchertest.role:web endpoints to connect to "
        "'osn-services-ip-addresses'")
    assert osn["destination"]["kind"] == "oci_services" and not osn["destination_is_internet_or_any"]


def test_oracle_documented_shapes():
    egress = zpr.parse_statement("in front-end:network VCN allow loadbalancer:web to connect to '0.0.0.0/0'")
    assert egress["parsed"] and egress["destination_is_internet_or_any"]
    assert egress["source"]["attribute"] == {"namespace": "oracle-zpr", "key": "loadbalancer", "value": "web"}

    two_vcn = zpr.parse_statement(
        "allow applications.app:webserver endpoints in applications.vcn:A VCN to connect to "
        "database.database:MySQL endpoints in database.vcn:B VCN")
    assert two_vcn["parsed"]
    names = {(a["namespace"], a["key"]) for a in two_vcn["attributes_referenced"]}
    assert names == {("applications", "app"), ("database", "database"), ("applications", "vcn"), ("database", "vcn")}

    private_cidr = zpr.parse_statement("in applications.apps:app1 VCN allow '10.0.0.0/16' to connect to apps:app1 endpoints")
    assert private_cidr["source"]["kind"] == "cidr" and not private_cidr["source_is_internet"]


def test_quoted_attribute_values_with_spaces():
    parsed = zpr.parse_statement(
        "in app:net VCN allow 'my-corp.biz:dev and test db' endpoints to connect to app:store endpoints")
    assert parsed["source"]["attribute"]["value"] == "dev and test db"


def test_unrecognised_statements_are_kept_and_never_read_as_restrictive():
    parsed = zpr.parse_statement("permit everything forever")
    assert parsed == {"statement": "permit everything forever", "parsed": False}
    out = zpr.summarize({"enabled": True, "zpr_status": "ENABLED"},
                        [zpr.policy_record({"statements": ["permit everything forever"]}, defined=set())], [], [])
    assert out["unparsed_statements"] == 1
    assert out["statements_without_protocol_restriction"] == 0


def test_dangling_attributes_are_flagged_only_when_definitions_were_read():
    statement = "in ghost.vcn:x VCN allow ghost.role:web endpoints to connect to app:db endpoints"
    defined = {("oracle-zpr", "app")}
    record = zpr.policy_record({"statements": [statement]}, defined=defined)
    assert record["statements"][0]["undefined_attributes"] == ["ghost.role", "ghost.vcn"]

    unread = zpr.policy_record({"statements": [statement]}, defined=None)
    assert "undefined_attributes" not in unread["statements"][0]
    out = zpr.summarize(None, [unread], [], [], definitions_read=False)
    assert out["statements_with_undefined_attributes"] is None
    assert out["zpr_enabled"] is None


def test_vcn_zpr_only_is_true_only_when_set():
    labelled = {"lifecycle_state": "AVAILABLE", "is_zpr_only": None,
                "security_attributes": {"fetchertest": {"vcn": {"mode": "enforce", "value": "test"}}}}
    record = zpr.vcn_record(labelled)
    assert record["zpr_enforced"] and record["is_zpr_only"] is False
    assert zpr.vcn_record({**labelled, "is_zpr_only": True})["is_zpr_only"] is True
    assert zpr.vcn_record({"lifecycle_state": "AVAILABLE"})["in_zpr"] is False
