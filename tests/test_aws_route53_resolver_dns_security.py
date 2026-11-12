"""aws_route53_resolver_dns_security reports each VPC's DNSSEC, DNS Firewall and query logging.

The test runs the real fetcher against a fake `aws` on PATH. The fake answers
with responses already shaped the way each --query asks for them. What it holds
the fetcher to: only COMPLETE firewall and ACTIVE query-log associations count,
a DNS Firewall Advanced rule has no domain list name, and a failed call reads
null (never "off" or "none") and still writes the evidence file.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "aws" / "route53_resolver_dns_security" / "fetcher.sh"

pytestmark = pytest.mark.skipif(
    not (shutil.which("bash") and shutil.which("jq")), reason="requires bash and jq"
)

FAKE_AWS = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
key = " ".join(args[:2])
if "--firewall-rule-group-id" in args:
    key += " " + args[args.index("--firewall-rule-group-id") + 1]
responses = json.load(open(os.environ["FAKE_AWS_RESPONSES"]))
if key not in responses:
    sys.stderr.write("An error occurred (AccessDeniedException): not authorized to perform " + key + "\n")
    sys.exit(254)
print(json.dumps(responses[key]))
"""


def _rule(name, action, list_id=None, block=None, threat=None):
    tp_id, kind, conf = threat or (None, None, None)
    return {"Name": name, "Priority": 1, "Action": action, "BlockResponse": block, "DomainListId": list_id,
            "FirewallThreatProtectionId": tp_id, "DnsThreatProtection": kind, "ConfidenceThreshold": conf}


RESPONSES = {
    "sts get-caller-identity": {"Account": "111122223333", "Arn": "arn:aws:iam::111122223333:role/test"},
    "ec2 describe-vpcs": [
        {"Id": "vpc-prod", "IsDefault": False, "Name": "prod"},
        {"Id": "vpc-stg", "IsDefault": False, "Name": "staging"},
        {"Id": "vpc-default", "IsDefault": True, "Name": None},
    ],
    "route53resolver list-resolver-dnssec-configs": [
        {"Id": "rdsc-1", "ResourceId": "vpc-prod", "ValidationStatus": "ENABLED"},
        {"Id": "rdsc-2", "ResourceId": "vpc-default", "ValidationStatus": "USE_LOCAL_RESOURCE_SETTING"},
        {"Id": "rdsc-3", "ResourceId": "vpc-deleted", "ValidationStatus": "ENABLED"},
    ],
    "route53resolver list-firewall-rule-group-associations": [
        {"VpcId": "vpc-prod", "RuleGroupId": "rslvr-frg-1", "Name": "a", "Priority": 101,
         "Status": "COMPLETE", "MutationProtection": "ENABLED"},
        {"VpcId": "vpc-prod", "RuleGroupId": "rslvr-frg-2", "Name": "b", "Priority": 200,
         "Status": "COMPLETE", "MutationProtection": "DISABLED"},
        {"VpcId": "vpc-stg", "RuleGroupId": "rslvr-frg-1", "Name": "c", "Priority": 101,
         "Status": "UPDATING", "MutationProtection": "DISABLED"},
    ],
    "route53resolver list-firewall-rules rslvr-frg-1": [
        _rule("block-threats", "BLOCK", "rslvr-fdl-aws", "NODATA"),
        _rule("alert-unnamed", "ALERT", "rslvr-fdl-elsewhere"),
    ],
    "route53resolver list-firewall-rules rslvr-frg-2": [
        _rule("tunneling", "BLOCK", None, "NXDOMAIN", ("rslvr-ftp-1", "DNS_TUNNELING", "HIGH")),
    ],
    "route53resolver list-firewall-domain-lists": [
        {"Id": "rslvr-fdl-aws", "Name": "AWSManagedDomainsAggregateThreatList",
         "ManagedOwnerName": "Route 53 Resolver DNS Firewall"},
    ],
    "route53resolver list-resolver-query-log-config-associations": [
        {"ResourceId": "vpc-prod", "ConfigId": "rqlc-1", "Status": "ACTIVE", "Error": "NONE"},
        {"ResourceId": "vpc-stg", "ConfigId": "rqlc-2", "Status": "ACTION_NEEDED", "Error": "DESTINATION_NOT_FOUND"},
    ],
}


def _run(tmp_path: Path, responses: dict) -> tuple[subprocess.CompletedProcess, dict]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "aws"
    exe.write_text(FAKE_AWS)
    exe.chmod(0o755)
    resp_file = tmp_path / "responses.json"
    resp_file.write_text(json.dumps(responses))
    evidence = tmp_path / "evidence"
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")} | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_AWS_RESPONSES": str(resp_file),
        "EVIDENCE_DIR": str(evidence),
        "FETCHER_STATUS_FILE": str(tmp_path / "status.json"),
        "AWS_DEFAULT_REGION": "us-gov-west-1",
    }
    # cwd is tmp_path so the fetcher's `[ -f .env ]` never sources the repo's.
    r = subprocess.run(["bash", str(FETCHER)], cwd=tmp_path, env=env, capture_output=True, text=True)
    (out,) = evidence.glob("*.json")
    assert out.name == "aws_route53_resolver_dns_security_ambient_us-gov-west-1.json"
    return r, json.loads(out.read_text())


def test_each_vpc_reports_dnssec_firewall_and_query_logging(tmp_path):
    r, doc = _run(tmp_path, RESPONSES)
    assert r.returncode == 0, r.stderr
    vpcs = {v["Id"]: v for v in doc["results"]}

    prod = vpcs["vpc-prod"]
    assert prod["DnssecValidation"] == "ENABLED"
    assert prod["DnsFirewall"]["Associated"] is True
    rules = {rule["Name"]: rule for g in prod["DnsFirewall"]["RuleGroups"] for rule in g["Rules"]}
    assert rules["block-threats"]["DomainListName"] == "AWSManagedDomainsAggregateThreatList"
    assert rules["alert-unnamed"]["DomainListName"] == "unknown"
    assert rules["tunneling"]["DomainListName"] is None
    assert rules["tunneling"]["FirewallThreatProtectionId"] == "rslvr-ftp-1"
    assert prod["QueryLogging"] == {"Enabled": True, "Associations": [
        {"ConfigId": "rqlc-1", "Status": "ACTIVE", "Error": "NONE"}]}

    stg = vpcs["vpc-stg"]
    assert stg["DnssecValidation"] == "NOT_CONFIGURED"
    # An association still UPDATING is listed but does not count as associated.
    assert stg["DnsFirewall"]["Associated"] is False
    assert [g["Status"] for g in stg["DnsFirewall"]["RuleGroups"]] == ["UPDATING"]
    assert stg["QueryLogging"]["Enabled"] is False
    assert stg["QueryLogging"]["Associations"][0]["Error"] == "DESTINATION_NOT_FOUND"

    default = vpcs["vpc-default"]
    assert default["Default"] is True and default["Name"] == ""
    assert default["DnssecValidation"] == "USE_LOCAL_RESOURCE_SETTING"
    assert default["DnsFirewall"] == {"Associated": False, "RuleGroups": []}

    assert [c["ResourceId"] for c in doc["OrphanedDnssecConfigs"]] == ["vpc-deleted"]


def test_a_failed_rule_group_read_is_null_not_empty(tmp_path):
    responses = {k: v for k, v in RESPONSES.items() if k != "route53resolver list-firewall-rules rslvr-frg-2"}
    r, doc = _run(tmp_path, responses)
    assert r.returncode == 1
    assert "list-firewall-rules (rslvr-frg-2) failed" in r.stderr
    prod = next(v for v in doc["results"] if v["Id"] == "vpc-prod")
    rules = {g["Id"]: g["Rules"] for g in prod["DnsFirewall"]["RuleGroups"]}
    assert rules["rslvr-frg-2"] is None and len(rules["rslvr-frg-1"]) == 2
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["code"] == "not_authorized" and "rslvr-frg-2" in status["error"]


def test_failed_list_calls_read_null_not_off(tmp_path):
    failing = ("route53resolver list-resolver-dnssec-configs",
               "route53resolver list-firewall-rule-group-associations",
               "route53resolver list-resolver-query-log-config-associations")
    r, doc = _run(tmp_path, {k: v for k, v in RESPONSES.items() if k not in failing})
    assert r.returncode == 1
    assert len(doc["results"]) == 3
    for vpc in doc["results"]:
        assert vpc["DnssecValidation"] is None
        assert vpc["DnsFirewall"] == {"Associated": None, "RuleGroups": None}
        assert vpc["QueryLogging"] == {"Enabled": None, "Associations": None}
    assert doc["OrphanedDnssecConfigs"] is None


def test_a_failed_vpc_list_does_not_mark_every_dnssec_config_orphaned(tmp_path):
    r, doc = _run(tmp_path, {k: v for k, v in RESPONSES.items() if k != "ec2 describe-vpcs"})
    assert r.returncode == 1
    assert doc["results"] == [] and doc["OrphanedDnssecConfigs"] is None
