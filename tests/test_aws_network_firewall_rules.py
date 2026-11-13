"""aws_network_firewall_rules counts the rules in every kind of stateful rule group.

A stateful rule group's rules come from one of three sources: a list of
StatefulRules, a Suricata RulesString, or a domain list (RulesSourceList).
Before 0.2.0 only the first was read, so a group written in Suricata or as a
domain list reported StatefulRuleCount 0, which reads as a group that does
nothing. The test runs the real fetcher against a fake `aws` on PATH.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER = REPO_ROOT / "fetchers" / "aws" / "network_firewall_rules" / "fetcher.sh"

pytestmark = pytest.mark.skipif(
    not (shutil.which("bash") and shutil.which("jq")), reason="requires bash and jq"
)

# Keyed on "service operation", plus the ARN for the describe calls that take
# one. A string response is printed as-is (the fetcher asks for --output text).
FAKE_AWS = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
key = " ".join(args[:2])
for flag in ("--firewall-arn", "--firewall-policy-arn", "--rule-group-arn"):
    if flag in args:
        key += " " + args[args.index(flag) + 1]
responses = json.load(open(os.environ["FAKE_AWS_RESPONSES"]))
if key not in responses:
    sys.stderr.write("fake aws: no response for " + key + "\n")
    sys.exit(254)
r = responses[key]
print(r if isinstance(r, str) else json.dumps(r))
"""

FW = "arn:aws:network-firewall:us-east-1:111122223333:firewall/edge"
POLICY = "arn:aws:network-firewall:us-east-1:111122223333:firewall-policy/edge"


def _rg(name: str) -> str:
    return f"arn:aws:network-firewall:us-east-1:111122223333:stateful-rulegroup/{name}"


STATELESS = "arn:aws:network-firewall:us-east-1:111122223333:stateless-rulegroup/drop-frags"

SURICATA = "\n".join([
    "# Egress policy",
    "",
    'pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"example.com"; \\',
    "    sid:1; rev:1;)",
    "  drop tcp $HOME_NET any -> $EXTERNAL_NET 22 (sid:2; rev:1;)",
    "   # drop udp any any -> any 53 (sid:3;)",
    'alert http any any -> any any (msg:"x"; sid:4; rev:1;)',
    "",
])


def _group(arn: str, kind: str, rules_source: dict) -> dict:
    return {
        "RuleGroupResponse": {"RuleGroupArn": arn, "RuleGroupName": arn.rsplit("/", 1)[1],
                              "Type": kind, "Capacity": 100},
        "RuleGroup": {"RulesSource": rules_source},
    }


def test_stateful_rule_count_reads_every_rules_source(tmp_path):
    groups = {
        _rg("five-tuple"): {"StatefulRules": [{"Action": "PASS"}, {"Action": "DROP"}]},
        _rg("suricata"): {"RulesString": SURICATA},
        _rg("domains"): {"RulesSourceList": {
            "Targets": [".example.com", "updates.example.org", "api.example.net"],
            "TargetTypes": ["TLS_SNI", "HTTP_HOST"], "GeneratedRulesType": "ALLOWLIST",
        }},
    }
    responses = {
        "sts get-caller-identity": {"Account": "111122223333", "Arn": "arn:aws:iam::111122223333:role/test"},
        "network-firewall list-firewalls": FW,
        f"network-firewall describe-firewall {FW}": {"Firewall": {
            "FirewallArn": FW, "FirewallName": "edge", "VpcId": "vpc-1",
            "FirewallPolicyArn": POLICY, "SubnetMappings": [{"SubnetId": "subnet-1"}],
        }},
        f"network-firewall describe-firewall-policy {POLICY}": {"FirewallPolicy": {
            "StatelessDefaultActions": ["aws:forward_to_sfe"],
            "StatelessFragmentDefaultActions": ["aws:drop"],
            "StatelessRuleGroupReferences": [{"ResourceArn": STATELESS, "Priority": 1}],
            "StatefulRuleGroupReferences": [{"ResourceArn": arn} for arn in groups],
        }},
        f"network-firewall describe-rule-group {STATELESS}": _group(STATELESS, "STATELESS", {
            "StatelessRulesAndCustomActions": {"StatelessRules": [{"Priority": 1}, {"Priority": 2}, {"Priority": 3}]},
        }),
        **{f"network-firewall describe-rule-group {arn}": _group(arn, "STATEFUL", src) for arn, src in groups.items()},
    }

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
        "AWS_DEFAULT_REGION": "us-east-1",
    }
    # cwd is tmp_path so the fetcher's `[ -f .env ]` never sources the repo's.
    r = subprocess.run(["bash", str(FETCHER)], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    (out,) = evidence.glob("*.json")
    (firewall,) = json.loads(out.read_text())["results"]

    counted = {
        g["RuleGroupName"]: (g["Type"], g["StatefulRuleCount"], g["StatelessRuleCount"], g["StatefulRuleSource"])
        for g in firewall["FirewallPolicy"]["RuleGroups"]
    }
    assert counted == {
        "drop-frags": ("STATELESS", 0, 3, None),
        "five-tuple": ("STATEFUL", 2, 0, "StatefulRules"),
        # Blank lines and comments (indented or not) are not rules; a rule
        # continued onto a second line with a backslash is one rule.
        "suricata": ("STATEFUL", 3, 0, "RulesString"),
        # One per domain, not one per domain per target type.
        "domains": ("STATEFUL", 3, 0, "RulesSourceList"),
    }
    # The new key is appended; the existing ones keep their order.
    assert list(firewall["FirewallPolicy"]["RuleGroups"][0]) == [
        "RuleGroupArn", "RuleGroupName", "Type", "Capacity",
        "StatefulRuleCount", "StatelessRuleCount", "StatefulRuleSource",
    ]
