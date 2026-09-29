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
            {"GroupId": f"sg-{i}", "IpPermissions": [tcp], "IpPermissionsEgress": [everything]}
            for i in range(n_groups)
        ]
    }


def test_security_groups_makes_the_same_calls_at_any_group_count(tmp_path):
    (tmp_path / "small").mkdir()
    (tmp_path / "large").mkdir()
    small, _ = _run(tmp_path / "small", "security_groups", _security_groups(5))
    large, payload = _run(tmp_path / "large", "security_groups", _security_groups(300))
    assert small == large == 2
    # Port-less (All traffic) rules are dropped, as the old per-group text read
    # dropped them -- validators/aws/sg_no_open_inbound_except_https.yaml
    # documents that blind spot. This pins it until it is fixed deliberately.
    assert payload["results"][0] == {
        "GroupId": "sg-0",
        "Rules": [{"Direction": "INBOUND RULES", "Protocol": "tcp", "FromPort": 443, "ToPort": 443, "CIDRs": "0.0.0.0/0"}],
    }


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
