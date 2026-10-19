"""aws_organizations_scp: a read that failed must never look like "no SCPs".

From a plain member account, describe-organization succeeds (any member may
call it) while list-roots / list-policies are AccessDenied. 0.2.0 still wrote
`"Roots": [], "ServiceControlPolicies": []`, which a reader takes for an
organization with no SCPs. These tests run the real fetcher against a fake
`aws` on PATH and assert what the evidence SAYS in each case: a full read, a
denied read, an organization with zero SCPs (which must be distinguishable from
the denied one), and the per-account effective-SCP walk.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "aws" / "organizations_scp" / "fetcher.sh"

pytestmark = pytest.mark.skipif(
    not (shutil.which("bash") and shutil.which("jq")), reason="requires bash and jq"
)

# Keyed on "service operation" plus the id argument when there is one, so the
# per-policy and per-level calls can each answer differently. A string value is
# printed as-is (the fetcher asks for --output text there); a dict with "error"
# is a failed call. Responses are already shaped the way the --query asks.
FAKE_AWS = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_AWS_LOG"], "a") as f:
    f.write(" ".join(args) + "\n")
key = " ".join(args[:2])
for flag in ("--policy-id", "--child-id", "--target-id"):
    if flag in args:
        key += " " + args[args.index(flag) + 1]
responses = json.load(open(os.environ["FAKE_AWS_RESPONSES"]))
if key not in responses:
    key = " ".join(args[:2])
if key not in responses:
    sys.stderr.write("fake aws: no response for " + key + "\n")
    sys.exit(254)
r = responses[key]
if isinstance(r, dict) and "error" in r:
    sys.stderr.write("\nAn error occurred (" + r["error"] + ") when calling the operation: " + r.get("message", "") + "\n")
    sys.exit(254)
print(r if isinstance(r, str) else json.dumps(r))
"""

MGMT = "111111111111"
IDENTITY = {"Account": "222222222222", "Arn": "arn:aws:sts::222222222222:assumed-role/reader/x"}
ORG = {"Id": "o-abc", "Arn": "arn:aws:organizations::111111111111:organization/o-abc", "MasterAccountId": MGMT}
ROOTS = [{"Id": "r-root", "Name": "Root",
          "PolicyTypes": [{"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}]}]
DENIED = {"error": "AccessDeniedException",
          "message": "You don't have permissions to access this resource."}


def _policy(pid: str, name: str) -> dict:
    return {"PolicySummary": {"Id": pid, "Arn": f"arn:aws:organizations::{MGMT}:policy/o-abc/service_control_policy/{pid}",
                              "Name": name, "Type": "SERVICE_CONTROL_POLICY", "AwsManaged": pid == "p-FullAWSAccess"},
            "Content": json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})}


def _full_org() -> dict:
    """An org: root -> ou-a -> ou-b -> 333333333333, and 444444444444 under ou-a."""
    listed = [["p-FullAWSAccess", "arn:p1", "FullAWSAccess", True], ["p-deny", "arn:p2", "DenyLeaveOrg", False]]
    return {
        "organizations describe-organization": ORG,
        "organizations list-roots": ROOTS,
        "organizations list-policies": listed,
        "organizations describe-policy p-FullAWSAccess": _policy("p-FullAWSAccess", "FullAWSAccess"),
        "organizations describe-policy p-deny": _policy("p-deny", "DenyLeaveOrg"),
        "organizations list-targets-for-policy p-FullAWSAccess": [
            {"TargetId": "r-root", "Type": "ROOT", "Name": "Root"}],
        "organizations list-targets-for-policy p-deny": [
            {"TargetId": "ou-a", "Type": "ORGANIZATIONAL_UNIT", "Name": "Workloads"},
            {"TargetId": "333333333333", "Type": "ACCOUNT", "Name": "prod"}],
        "organizations list-parents 333333333333": "ou-b\tORGANIZATIONAL_UNIT",
        "organizations list-parents 444444444444": "ou-a\tORGANIZATIONAL_UNIT",
        "organizations list-parents ou-b": "ou-a\tORGANIZATIONAL_UNIT",
        "organizations list-parents ou-a": "r-root\tROOT",
        "organizations list-parents 111111111111": "r-root\tROOT",
        "organizations list-accounts": ["111111111111", "333333333333", "444444444444"],
    }


def _run(tmp_path: Path, responses: dict, **env_extra: str) -> tuple[subprocess.CompletedProcess, dict, list[str]]:
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
    status_file = tmp_path / "status.json"
    env = {
        k: v for k, v in os.environ.items() if not k.startswith("AWS_") and k != "SCP_EFFECTIVE_ACCOUNTS"
    } | {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_AWS_LOG": str(log),
        "FAKE_AWS_RESPONSES": str(resp_file),
        "EVIDENCE_DIR": str(evidence),
        "FETCHER_STATUS_FILE": str(status_file),
        "AWS_DEFAULT_REGION": "us-east-1",
        **env_extra,
    }
    # cwd is tmp_path so the fetcher's `[ -f .env ]` never sources the repo's.
    r = subprocess.run(["bash", str(FETCHER)], cwd=tmp_path, env=env, capture_output=True, text=True)
    (out,) = evidence.glob("*.json")
    record = json.loads(out.read_text())["results"]
    assert len(record) == 1
    return r, record[0], log.read_text().splitlines()


def _status(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "status.json").read_text())


def test_full_read_is_ok_and_keeps_the_existing_keys_first(tmp_path):
    r, rec, _ = _run(tmp_path, _full_org())
    assert r.returncode == 0, r.stderr
    # Existing keys keep their place; what was learned about the read follows.
    assert list(rec) == ["Organization", "Roots", "ServiceControlPolicies",
                         "OrganizationsInUse", "ScpsEnabled", "PolicyRead"]
    assert rec["PolicyRead"] == {"Status": "ok", "Reason": None}
    assert rec["ScpsEnabled"] is True
    assert rec["OrganizationsInUse"] is True
    assert [p["Name"] for p in rec["ServiceControlPolicies"]] == ["FullAWSAccess", "DenyLeaveOrg"]
    assert rec["ServiceControlPolicies"][0]["Content"]["Statement"][0]["Action"] == "*"
    assert "EffectiveScps" not in rec, "the effective walk is off unless asked for"


def test_member_account_denied_is_null_not_empty(tmp_path):
    """The bug: describe-organization works from any member, the SCP reads don't."""
    r, rec, _ = _run(tmp_path, {
        "organizations describe-organization": ORG,
        "organizations list-roots": DENIED,
        "organizations list-policies": DENIED,
    })
    assert r.returncode == 1
    assert _status(tmp_path)["code"] == "not_authorized"
    assert rec["Roots"] is None
    assert rec["ServiceControlPolicies"] is None
    assert rec["ScpsEnabled"] is None
    assert rec["PolicyRead"]["Status"] == "denied"
    assert rec["PolicyRead"]["Reason"].startswith("list-roots: An error occurred (AccessDeniedException)")
    assert rec["Organization"] == ORG


def test_zero_scps_is_distinguishable_from_denied(tmp_path):
    r, rec, _ = _run(tmp_path, {
        "organizations describe-organization": ORG,
        "organizations list-roots": [{"Id": "r-root", "PolicyTypes": []}],
        "organizations list-policies": [],
    })
    assert r.returncode == 0, r.stderr
    assert rec["ServiceControlPolicies"] == []
    assert rec["PolicyRead"] == {"Status": "ok", "Reason": None}
    assert rec["ScpsEnabled"] is False


def test_one_unreadable_policy_marks_the_read_incomplete(tmp_path):
    responses = _full_org()
    responses["organizations list-targets-for-policy p-deny"] = DENIED
    r, rec, _ = _run(tmp_path, responses)
    assert r.returncode == 1
    by_name = {p["Name"]: p for p in rec["ServiceControlPolicies"]}
    assert by_name["DenyLeaveOrg"]["Targets"] is None, "an unread target list is null, not []"
    assert by_name["FullAWSAccess"]["Targets"] == [{"TargetId": "r-root", "Type": "ROOT", "Name": "Root"}]
    assert rec["PolicyRead"]["Status"] == "denied"
    assert "list-targets-for-policy (p-deny)" in rec["PolicyRead"]["Reason"]


def test_expired_credentials_are_error_not_denied(tmp_path):
    expired = {"error": "ExpiredTokenException", "message": "The security token included in the request is expired"}
    r, rec, _ = _run(tmp_path, {
        "organizations describe-organization": ORG,
        "organizations list-roots": expired,
        "organizations list-policies": expired,
    })
    assert r.returncode == 1
    assert rec["PolicyRead"]["Status"] == "error"
    assert rec["ServiceControlPolicies"] is None


def test_standalone_account_is_not_enabled_and_exits_zero(tmp_path):
    r, rec, _ = _run(tmp_path, {
        "organizations describe-organization": {
            "error": "AWSOrganizationsNotInUseException",
            "message": "Your account is not a member of an organization."},
    }, SCP_EFFECTIVE_ACCOUNTS="all")
    assert r.returncode == 0, r.stderr
    assert rec["OrganizationsInUse"] is False
    assert rec["ServiceControlPolicies"] == []
    assert rec["PolicyRead"]["Status"] == "not_enabled"
    assert rec["EffectiveScpsRead"]["Status"] == "not_enabled"
    assert rec["EffectiveScps"] == []


def test_effective_scps_walk_to_the_root_from_collected_targets(tmp_path):
    r, rec, calls = _run(tmp_path, _full_org(), SCP_EFFECTIVE_ACCOUNTS=" 333333333333, 444444444444,333333333333")
    assert r.returncode == 0, r.stderr
    assert rec["EffectiveScpsRead"] == {"Status": "ok", "Reason": None}
    prod, other = rec["EffectiveScps"]  # duplicates dropped, order kept
    assert prod["AccountId"] == "333333333333"
    assert prod["IsManagementAccount"] is False
    assert prod["Status"] == "ok"
    assert prod["Path"] == [
        {"Type": "ACCOUNT", "Id": "333333333333"},
        {"Type": "ORGANIZATIONAL_UNIT", "Id": "ou-b"},
        {"Type": "ORGANIZATIONAL_UNIT", "Id": "ou-a"},
        {"Type": "ROOT", "Id": "r-root"},
    ]
    assert prod["Policies"] == [
        {"Id": "p-deny", "Name": "DenyLeaveOrg", "AttachedToType": "ACCOUNT", "AttachedToId": "333333333333"},
        {"Id": "p-deny", "Name": "DenyLeaveOrg", "AttachedToType": "ORGANIZATIONAL_UNIT", "AttachedToId": "ou-a"},
        {"Id": "p-FullAWSAccess", "Name": "FullAWSAccess", "AttachedToType": "ROOT", "AttachedToId": "r-root"},
    ]
    assert [p["AttachedToId"] for p in other["Policies"]] == ["ou-a", "r-root"]
    # The full read already says what is attached where: no per-level calls, no
    # second describe-policy, and the parent of ou-a is asked once, not twice.
    assert not any("list-policies-for-target" in c for c in calls)
    assert sum("describe-policy" in c for c in calls) == 2
    assert sum("list-parents --child-id ou-a" in c for c in calls) == 1


def test_effective_all_enumerates_accounts_and_flags_the_management_account(tmp_path):
    r, rec, _ = _run(tmp_path, _full_org(), SCP_EFFECTIVE_ACCOUNTS="All")
    assert r.returncode == 0, r.stderr
    ids = [a["AccountId"] for a in rec["EffectiveScps"]]
    assert ids == ["111111111111", "333333333333", "444444444444"]
    mgmt = rec["EffectiveScps"][0]
    assert mgmt["IsManagementAccount"] is True  # SCPs do not apply to it


def test_effective_falls_back_to_per_level_calls_when_targets_were_not_read(tmp_path):
    responses = _full_org()
    responses["organizations list-targets-for-policy p-deny"] = DENIED
    responses |= {
        "organizations list-policies-for-target 444444444444": [],
        "organizations list-policies-for-target ou-a": [{"Id": "p-deny", "Name": "DenyLeaveOrg"}],
        "organizations list-policies-for-target r-root": [{"Id": "p-FullAWSAccess", "Name": "FullAWSAccess"}],
    }
    r, rec, calls = _run(tmp_path, responses, SCP_EFFECTIVE_ACCOUNTS="444444444444")
    assert r.returncode == 1  # the targets read failed; the walk itself did not
    (acct,) = rec["EffectiveScps"]
    assert acct["Status"] == "ok"
    assert [(p["Id"], p["AttachedToId"]) for p in acct["Policies"]] == [("p-deny", "ou-a"), ("p-FullAWSAccess", "r-root")]
    assert sum("list-policies-for-target" in c for c in calls) == 3


def test_one_unreadable_account_does_not_cost_the_others(tmp_path):
    responses = _full_org()
    responses["organizations list-parents 444444444444"] = DENIED
    r, rec, _ = _run(tmp_path, responses, SCP_EFFECTIVE_ACCOUNTS="333333333333,444444444444,nope")
    assert r.returncode == 1
    assert _status(tmp_path)["code"] == "not_authorized"
    good, denied, bad = rec["EffectiveScps"]
    assert good["Status"] == "ok" and len(good["Policies"]) == 3
    assert denied == {"AccountId": "444444444444", "IsManagementAccount": False, "Status": "denied",
                      "Reason": denied["Reason"], "Path": None, "Policies": None}
    assert denied["Reason"].startswith("list-parents (444444444444): An error occurred (AccessDeniedException)")
    assert bad["Status"] == "error" and bad["Policies"] is None
    assert rec["EffectiveScpsRead"]["Status"] == "denied"
    assert rec["EffectiveScpsRead"]["Reason"].startswith("444444444444: list-parents")


def test_effective_list_accounts_denied_is_null(tmp_path):
    responses = _full_org()
    responses["organizations list-accounts"] = DENIED
    r, rec, _ = _run(tmp_path, responses, SCP_EFFECTIVE_ACCOUNTS="all")
    assert r.returncode == 1
    assert rec["EffectiveScps"] is None
    assert rec["EffectiveScpsRead"]["Status"] == "denied"


def test_a_malformed_account_id_is_bad_config(tmp_path):
    r, rec, _ = _run(tmp_path, _full_org(), SCP_EFFECTIVE_ACCOUNTS="12345")
    assert r.returncode == 1
    assert _status(tmp_path)["code"] == "bad_config"
    assert rec["EffectiveScps"][0]["Status"] == "error"
