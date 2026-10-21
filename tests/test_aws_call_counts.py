"""AWS fetchers whose call count must not grow with the account.

A customer's Landing Zone Accelerator accounts, with thousands of EBS snapshots
under AWS Backup and DLM, ran ebs_snapshot_status past the runner's 600s
timeout: it made one CLI call per snapshot. The fix made the count constant, and
these tests hold it there. Each runs the real fetcher against a fake `aws` on
PATH at two account sizes and asserts the number of calls is the same.

The fake answers with responses already shaped the way the fetcher's --query
asks for them, so it needs no JMESPath. It is keyed on "service operation", plus
a marker for the one call that differs only by a flag.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AWS_FETCHERS = REPO_ROOT / "fetchers" / "aws"

pytestmark = pytest.mark.skipif(
    not (shutil.which("bash") and shutil.which("jq")), reason="requires bash and jq"
)

FAKE_AWS = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_AWS_LOG"], "a") as f:
    f.write(" ".join(args) + "\n")
key = " ".join(args[:2])
if "--restorable-by-user-ids" in args:
    key += " public"
responses = json.load(open(os.environ["FAKE_AWS_RESPONSES"]))
if key not in responses:
    sys.stderr.write("fake aws: no response for " + key + "\n")
    sys.exit(254)
print(json.dumps(responses[key]))
"""

IDENTITY = {"Account": "111122223333", "Arn": "arn:aws:iam::111122223333:role/test"}


def _run(tmp_path: Path, fetcher: str, responses: dict) -> tuple[int, dict]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    exe = bin_dir / "aws"
    exe.write_text(FAKE_AWS)
    exe.chmod(0o755)
    resp_file = tmp_path / "responses.json"
    resp_file.write_text(json.dumps({"sts get-caller-identity": IDENTITY, **responses}))
    log = tmp_path / "calls.log"
    log.write_text("")
    evidence = tmp_path / "evidence"
    env = {
        k: v for k, v in os.environ.items() if not k.startswith("AWS_")
    } | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_AWS_LOG": str(log),
        "FAKE_AWS_RESPONSES": str(resp_file),
        "EVIDENCE_DIR": str(evidence),
        "AWS_DEFAULT_REGION": "us-east-1",
    }
    # cwd is tmp_path so the fetcher's `[ -f .env ]` never sources the repo's.
    r = subprocess.run(
        ["bash", str(AWS_FETCHERS / fetcher / "fetcher.sh")],
        cwd=tmp_path, env=env, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    (out,) = evidence.glob("*.json")
    return len(log.read_text().splitlines()), json.loads(out.read_text())


def _ebs(n_snapshots: int) -> dict:
    snaps = [
        {"SnapshotId": f"snap-{i}", "VolumeId": f"vol-{i % 7}", "Encrypted": i % 2 == 0,
         "StartTime": "2026-01-01T00:00:00.000Z"}
        for i in range(n_snapshots)
    ]
    return {
        "ec2 describe-snapshots": snaps,
        "ec2 describe-snapshots public": [s["SnapshotId"] for s in snaps if s["SnapshotId"].endswith("3")],
        "ec2 describe-volumes": [{"VolumeId": f"vol-{j}", "Encrypted": True} for j in range(9)],
    }


def test_ebs_snapshot_status_makes_the_same_calls_at_any_snapshot_count(tmp_path):
    (tmp_path / "small").mkdir()
    (tmp_path / "large").mkdir()
    small, _ = _run(tmp_path / "small", "ebs_snapshot_status", _ebs(20))
    large, payload = _run(tmp_path / "large", "ebs_snapshot_status", _ebs(400))
    assert small == large == 4

    by_volume = {r["VolumeId"]: r for r in payload["results"]}
    assert by_volume["vol-3"]["HasSnapshot"] is True
    assert by_volume["vol-8"] == {"VolumeId": "vol-8", "Encrypted": True, "HasSnapshot": False, "Snapshots": []}
    snaps = [s for r in payload["results"] for s in r["Snapshots"]]
    assert len(snaps) == 400
    assert {s["SnapshotId"] for s in snaps if s["Public"]} == {f"snap-{i}" for i in range(400) if str(i).endswith("3")}
    assert list(snaps[0]) == ["SnapshotId", "VolumeId", "Encrypted", "StartTime", "Public"]


def _security_groups(n_groups: int) -> dict:
    tcp = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    everything = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    return {
        "ec2 describe-security-groups": [
            {"GroupId": f"sg-{i}", "GroupName": f"group-{i}", "VpcId": "vpc-1",
             "IpPermissions": [tcp], "IpPermissionsEgress": [everything]}
            for i in range(n_groups)
        ]
    }


def test_security_groups_makes_the_same_calls_at_any_group_count(tmp_path):
    (tmp_path / "small").mkdir()
    (tmp_path / "large").mkdir()
    small, _ = _run(tmp_path / "small", "security_groups", _security_groups(5))
    large, payload = _run(tmp_path / "large", "security_groups", _security_groups(300))
    assert small == large == 2
    assert payload["results"][0] == {
        "GroupId": "sg-0",
        "Rules": [
            {"Direction": "INBOUND RULES", "Protocol": "tcp", "FromPort": 443, "ToPort": 443,
             "CIDRs": "0.0.0.0/0", "IPv6CIDRs": "", "SecurityGroupIds": "", "PrefixListIds": ""},
            {"Direction": "OUTBOUND RULES", "Protocol": "-1", "FromPort": None, "ToPort": None,
             "CIDRs": "0.0.0.0/0", "IPv6CIDRs": "", "SecurityGroupIds": "", "PrefixListIds": ""},
        ],
        "GroupName": "group-0",
        "VpcId": "vpc-1",
    }
    # Keys are only ever appended: validators match on this order.
    assert list(payload["results"][0]) == ["GroupId", "Rules", "GroupName", "VpcId"]


def test_security_groups_keeps_all_traffic_and_ipv6_rules(tmp_path):
    # Each shape here was missing from the evidence before 0.3.0: an all-traffic
    # rule (protocol -1, no ports) was dropped outright, and IPv6 ranges were
    # never read, so a rule open only to ::/0 looked closed.
    perms = [
        {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "10.0.0.0/8"}, {"CidrIp": "0.0.0.0/0"}],
         "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/32"}, {"CidrIpv6": "::/0"}]},
        {"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
         "UserIdGroupPairs": [{"GroupId": "sg-app"}]},
    ]
    _, payload = _run(tmp_path, "security_groups", {
        "ec2 describe-security-groups": [{"GroupId": "sg-1", "IpPermissions": perms, "IpPermissionsEgress": []}],
    })
    rules = payload["results"][0]["Rules"]
    # Keys are only ever appended: validators match on this order.
    assert all(list(r) == ["Direction", "Protocol", "FromPort", "ToPort", "CIDRs", "IPv6CIDRs",
                           "SecurityGroupIds", "PrefixListIds"] for r in rules)
    assert [(r["Protocol"], r["FromPort"], r["ToPort"], r["CIDRs"], r["IPv6CIDRs"]) for r in rules] == [
        ("-1", None, None, "0.0.0.0/0", ""),
        ("tcp", 22, 22, "", "::/0"),
        ("tcp", 443, 443, "10.0.0.0/8, 0.0.0.0/0", "2001:db8::/32, ::/0"),
        ("icmp", -1, -1, "0.0.0.0/0", ""),
        ("tcp", 5432, 5432, "", ""),
    ]


def test_security_groups_keeps_group_and_prefix_list_sources(tmp_path):
    # Before 0.4.0 a rule sourced from another security group or a prefix list
    # came out with empty CIDRs and nothing else, so it read as a rule that
    # allowed nothing; the group's name and VPC were not recorded either.
    inbound = [
        {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
         "UserIdGroupPairs": [{"GroupId": "sg-app", "UserId": "111122223333"},
                              {"GroupId": "sg-peer", "UserId": "444455556666",
                               "VpcPeeringConnectionId": "pcx-1"}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
         "PrefixListIds": [{"PrefixListId": "pl-cloudfront"}, {"PrefixListId": "pl-office"}]},
    ]
    outbound = [
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
         "PrefixListIds": [{"PrefixListId": "pl-s3"}]},
        {"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-self"}]},
    ]
    _, payload = _run(tmp_path, "security_groups", {
        "ec2 describe-security-groups": [{
            "GroupId": "sg-1", "GroupName": "db", "VpcId": "vpc-9",
            "IpPermissions": inbound, "IpPermissionsEgress": outbound,
        }],
    })
    (group,) = payload["results"]
    assert (group["GroupId"], group["GroupName"], group["VpcId"]) == ("sg-1", "db", "vpc-9")
    assert [(r["Direction"], r["CIDRs"], r["SecurityGroupIds"], r["PrefixListIds"]) for r in group["Rules"]] == [
        # Same-account references are the bare group id; another account's are
        # <account-id>/<group-id>, as the console writes them.
        ("INBOUND RULES", "", "sg-app, 444455556666/sg-peer", ""),
        ("INBOUND RULES", "10.0.0.0/8", "", "pl-cloudfront, pl-office"),
        ("OUTBOUND RULES", "", "", "pl-s3"),
        ("OUTBOUND RULES", "", "sg-self", ""),
    ]


def _iam_roles(n_roles: int) -> dict:
    roles = [
        {"RoleName": f"role-{i}", "Arn": f"arn:aws:iam::111122223333:role/role-{i}",
         "CreateDate": "2024-01-01T00:00:00+00:00", "MaxSessionDuration": 3600,
         "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}
        for i in range(n_roles)
    ]
    details = [
        {"RoleName": r["RoleName"],
         "AttachedManagedPolicies": [{"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}],
         "InstanceProfileList": [], "Tags": None}
        for r in roles
    ]
    return {
        "iam list-roles": roles,
        "iam get-account-authorization-details": details,
        "iam get-account-password-policy": {"MinimumPasswordLength": 14},
    }


def test_iam_roles_makes_the_same_calls_at_any_role_count(tmp_path):
    (tmp_path / "small").mkdir()
    (tmp_path / "large").mkdir()
    small, _ = _run(tmp_path / "small", "iam_roles", _iam_roles(3))
    large, payload = _run(tmp_path / "large", "iam_roles", _iam_roles(200))
    assert small == large == 4
    assert payload["results"][0] == {
        "RoleName": "role-0",
        "Arn": "arn:aws:iam::111122223333:role/role-0",
        "CreateDate": "2024-01-01T00:00:00+00:00",
        "Description": None,
        "MaxSessionDuration": 3600,
        "TrustPolicy": {"Version": "2012-10-17", "Statement": []},
        "AttachedPolicies": [["ReadOnlyAccess", "arn:aws:iam::aws:policy/ReadOnlyAccess"]],
        "InstanceProfiles": [],
        "Tags": [],
    }
    assert payload["results"][-1] == {"Type": "PasswordPolicy", "Policy": {"MinimumPasswordLength": 14}}


def test_iam_mfa_status_tells_security_keys_from_virtual_devices(tmp_path):
    # Before 0.2.0 every ARN serial was "virtual", so a FIDO security key
    # (arn:...:u2f/...), the phishing-resistant factor, read as an app.
    acct = "arn:aws:iam::111122223333"
    devices = [
        [f"{acct}:u2f/user/alice/yubikey-ABCDEFGHIJKLMNOPQRSTUVWXYZ", "2026-01-01T00:00:00Z"],
        [f"{acct}:mfa/alice-phone", "2026-01-02T00:00:00Z"],
        ["GAHT12345678", "2026-01-03T00:00:00Z"],
        ["arn:aws-us-gov:iam::111122223333:u2f/user/alice/key2", "2026-01-04T00:00:00Z"],
        [f"{acct}:sms-mfa/alice", "2026-01-05T00:00:00Z"],
    ]
    _, payload = _run(tmp_path, "iam_mfa_status", {
        "iam get-account-summary": {"AccountMFAEnabled": 1},
        "iam list-virtual-mfa-devices": [],
        "iam list-users": ["alice"],
        "iam list-mfa-devices": devices,
    })
    (user,) = payload["results"]["users"]
    assert user["MFAEnabled"] is True
    assert [d["Type"] for d in user["MFADevices"]] == ["fido", "virtual", "hardware", "fido", "unknown"]
    assert all(list(d) == ["SerialNumber", "EnableDate", "Type"] for d in user["MFADevices"])
    assert payload["results"]["root_account"] == {"RootMFAEnabled": True, "RootHardwareMFA": True}


def test_iam_policies_lists_boundary_use_apart_from_attachments(tmp_path):
    # Before 0.3.0 an entity that only used the policy as its permissions
    # boundary was listed under AttachedUsers / AttachedRoles.
    arn = "arn:aws:iam::111122223333:policy/guardrail"
    other = "arn:aws:iam::111122223333:policy/other"
    policy = {
        "PolicyName": "guardrail", "PolicyId": "ANPA0", "Arn": arn,
        "CreateDate": "2024-01-01T00:00:00Z", "UpdateDate": "2024-01-01T00:00:00Z",
        "PolicyVersionList": [{"IsDefaultVersion": True, "Document": {"Version": "2012-10-17", "Statement": []}}],
    }
    _, payload = _run(tmp_path, "iam_policies", {
        "iam list-policies": [arn],
        "iam get-account-authorization-details": {
            "Policies": [policy],
            "Users": [
                {"Name": "attaches", "Attached": [arn], "Boundary": None},
                {"Name": "bounded", "Attached": [other], "Boundary": arn},
                {"Name": "both", "Attached": [arn], "Boundary": arn},
                {"Name": "neither", "Attached": None, "Boundary": other},
            ],
            "Groups": [{"Name": "ops", "Attached": [arn]}],
            "Roles": [
                {"Name": "app", "Attached": [], "Boundary": arn},
                {"Name": "admin", "Attached": [arn], "Boundary": None},
            ],
        },
    })
    (result,) = payload["results"]
    assert result["AttachedGroups"] == ["ops"]
    assert result["AttachedUsers"] == ["attaches", "both"]
    assert result["AttachedRoles"] == ["admin"]
    assert result["BoundaryUsers"] == ["bounded", "both"]
    assert result["BoundaryRoles"] == ["app"]
    # The new keys are appended, so patterns that read the existing order still match.
    assert list(result)[-5:] == ["AttachedGroups", "AttachedUsers", "AttachedRoles", "BoundaryUsers", "BoundaryRoles"]
