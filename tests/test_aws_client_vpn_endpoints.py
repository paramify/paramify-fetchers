"""aws_client_vpn_endpoints reports each Client VPN endpoint's split tunnel, associations, rules and routes.

The test runs the real fetcher against a fake `aws` on PATH. The fake answers
with responses already shaped the way each --query asks for them. A failed
per-endpoint call reads null, never an empty list, and the run still writes
the evidence file. No endpoints is a successful empty result.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "aws" / "client_vpn_endpoints" / "fetcher.sh"

pytestmark = pytest.mark.skipif(
    not (shutil.which("bash") and shutil.which("jq")), reason="requires bash and jq"
)

FAKE_AWS = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
key = " ".join(args[:2])
if "--client-vpn-endpoint-id" in args:
    key += " " + args[args.index("--client-vpn-endpoint-id") + 1]
responses = json.load(open(os.environ["FAKE_AWS_RESPONSES"]))
if key not in responses:
    sys.stderr.write("An error occurred (AccessDeniedException): not authorized to perform " + key + "\n")
    sys.exit(254)
print(json.dumps(responses[key]))
"""


def _endpoint(eid, name, split):
    return {
        "Id": eid, "Name": name, "Description": "remote access", "Status": "available",
        "StatusMessage": None, "SplitTunnel": split, "VpnProtocol": "openvpn",
        "TransportProtocol": "udp", "VpnPort": 443, "ClientCidrBlock": "10.1.0.0/22",
        "DnsServers": ["10.0.0.2"], "DnsName": eid + ".example.vpn", "VpcId": "vpc-1",
        "SecurityGroupIds": ["sg-1"], "ServerCertificateArn": "arn:aws:acm:us-gov-west-1:111122223333:certificate/server",
        "Authentication": [{
            "Type": "federated-authentication", "DirectoryId": None,
            "ClientRootCertificateChainArn": None,
            "SamlProviderArn": "arn:aws:iam::111122223333:saml-provider/Example",
            "SelfServiceSamlProviderArn": None,
        }],
        "ConnectionLogging": {"Enabled": True, "LogGroup": "vpn", "LogStream": "connections"},
        "SessionTimeoutHours": 24, "SelfServicePortal": "disabled", "ClientConnectEnabled": False,
        "RouteEnforcement": True, "DisconnectOnSessionTimeout": True,
    }


RESPONSES = {
    "sts get-caller-identity": {"Account": "111122223333", "Arn": "arn:aws:iam::111122223333:role/test"},
    "ec2 describe-client-vpn-endpoints": [
        _endpoint("cvpn-endpoint-pre", "pre-vpn", True),
        _endpoint("cvpn-endpoint-prod", None, False),
    ],
    "ec2 describe-client-vpn-target-networks cvpn-endpoint-pre": [
        {"AssociationId": "cvpn-assoc-1", "VpcId": "vpc-1", "SubnetId": "subnet-a",
         "Status": "associated", "SecurityGroupIds": ["sg-1"]},
    ],
    "ec2 describe-client-vpn-target-networks cvpn-endpoint-prod": [],
    "ec2 describe-client-vpn-authorization-rules cvpn-endpoint-pre": [
        {"DestinationCidr": "10.0.0.0/16", "AuthorizeAllGroups": False, "AccessGroupId": "group-eng",
         "Description": "engineering", "Status": "active"},
        {"DestinationCidr": "10.2.0.0/16", "AuthorizeAllGroups": True, "AccessGroupId": None,
         "Description": "everyone", "Status": "active"},
    ],
    "ec2 describe-client-vpn-authorization-rules cvpn-endpoint-prod": [],
    "ec2 describe-client-vpn-routes cvpn-endpoint-pre": [
        {"DestinationCidr": "10.0.0.0/16", "TargetSubnet": "subnet-a", "Origin": "add-route",
         "Type": "Nat", "Status": "active", "Description": "app"},
    ],
    "ec2 describe-client-vpn-routes cvpn-endpoint-prod": [],
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
    r = subprocess.run(["bash", str(FETCHER)], cwd=tmp_path, env=env, capture_output=True, text=True)
    (out,) = evidence.glob("*.json")
    assert out.name == "aws_client_vpn_endpoints_ambient_us-gov-west-1.json"
    return r, json.loads(out.read_text())


def test_each_endpoint_reports_split_tunnel_associations_rules_and_routes(tmp_path):
    r, doc = _run(tmp_path, RESPONSES)
    assert r.returncode == 0, r.stderr
    by_id = {e["Id"]: e for e in doc["results"]}

    pre = by_id["cvpn-endpoint-pre"]
    assert pre["Name"] == "pre-vpn" and pre["SplitTunnel"] is True
    assert pre["TargetNetworks"] == [{
        "AssociationId": "cvpn-assoc-1", "VpcId": "vpc-1", "SubnetId": "subnet-a",
        "Status": "associated", "SecurityGroupIds": ["sg-1"],
    }]
    assert pre["AuthorizationRules"][0]["AccessGroupId"] == "group-eng"
    assert pre["AuthorizationRules"][1]["AuthorizeAllGroups"] is True
    assert pre["Routes"][0]["Origin"] == "add-route"
    assert pre["Authentication"][0]["Type"] == "federated-authentication"
    assert pre["ConnectionLogging"]["Enabled"] is True

    prod = by_id["cvpn-endpoint-prod"]
    assert prod["Name"] == "" and prod["SplitTunnel"] is False
    assert prod["TargetNetworks"] == [] and prod["AuthorizationRules"] == [] and prod["Routes"] == []


def test_no_endpoints_is_a_successful_empty_result(tmp_path):
    responses = {k: v for k, v in RESPONSES.items() if k == "sts get-caller-identity"}
    responses["ec2 describe-client-vpn-endpoints"] = []
    r, doc = _run(tmp_path, responses)
    assert r.returncode == 0, r.stderr
    assert doc["results"] == []


def test_a_failed_per_endpoint_call_reads_null_not_empty(tmp_path):
    responses = {k: v for k, v in RESPONSES.items()
                 if k != "ec2 describe-client-vpn-routes cvpn-endpoint-pre"}
    r, doc = _run(tmp_path, responses)
    assert r.returncode == 1
    assert "describe-client-vpn-routes (cvpn-endpoint-pre) failed" in r.stderr
    pre = next(e for e in doc["results"] if e["Id"] == "cvpn-endpoint-pre")
    assert pre["Routes"] is None
    assert len(pre["AuthorizationRules"]) == 2
    prod = next(e for e in doc["results"] if e["Id"] == "cvpn-endpoint-prod")
    assert prod["Routes"] == []
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["code"] == "not_authorized" and "cvpn-endpoint-pre" in status["error"]


def test_a_failed_endpoint_list_does_not_look_like_no_vpn(tmp_path):
    r, doc = _run(tmp_path, {k: v for k, v in RESPONSES.items() if k != "ec2 describe-client-vpn-endpoints"})
    assert r.returncode == 1
    assert doc["results"] == []
    assert "describe-client-vpn-endpoints failed" in r.stderr
