"""Run the real fetcher against AWS fixtures without credentials or network access.

Run with python -m unittest discover -s tests -p test_aws_detect_new_resource.py
Requires Bash and jq.
"""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
NAME = "audit-resource-config-changes"
TOPIC = "arn:aws:sns:us-east-1:123456789012:" + NAME


@unittest.skipUnless(shutil.which("bash") and shutil.which("jq"), "requires bash and jq")
class DetectNewResourceTests(unittest.TestCase):
    def test_trigger_validation(self):
        rule = {"Name": NAME, "State": "ENABLED", "EventPattern": json.dumps({"source": ["aws.config"]})}
        base = {
            "sts get-caller-identity": {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/test"},
            "configservice describe-configuration-recorders": [],
            "configservice describe-configuration-recorder-status": [],
            "configservice describe-delivery-channels": [],
            "events list-rules": [rule],
            "events describe-rule": rule,
            "events list-targets-by-rule": [{"Arn": TOPIC}],
            "sns list-topics": [{"TopicArn": TOPIC}],
            "sns list-subscriptions-by-topic": [],
        }
        cases = [
            ("event", {}, "NOT_APPLICABLE", "PASS", "PASS", "PASS"),
            ("disabled", {"State": "DISABLED"}, "NOT_APPLICABLE", "FAIL", "PASS", "PASS"),
            ("wrong_target", {}, "NOT_APPLICABLE", "PASS", "PASS", "FAIL"),
            ("missing_topic", {}, "NOT_APPLICABLE", "PASS", "PASS", "FAIL"),
            ("missing_rule", {}, "FAIL", "FAIL", "FAIL", "FAIL"),
            ("no_trigger", {"EventPattern": ""}, "FAIL", "PASS", "FAIL", "PASS"),
            ("bad_pattern", {"EventPattern": "{"}, "FAIL", "PASS", "FAIL", "PASS"),
            ("empty_pattern", {"EventPattern": "{}"}, "FAIL", "PASS", "FAIL", "PASS"),
            ("scheduled", {"EventPattern": "", "ScheduleExpression": "rate(5 minutes)"}, "PASS", "PASS", "NOT_APPLICABLE", "PASS"),
            ("slow_schedule", {"EventPattern": "", "ScheduleExpression": "rate(10 minutes)"}, "FAIL", "PASS", "NOT_APPLICABLE", "PASS"),
            ("both_triggers", {"ScheduleExpression": "rate(10 minutes)"}, "FAIL", "PASS", "PASS", "PASS"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            # Stage with Unix newlines so Windows checkouts can run under WSL.
            for relative in ["aws/detect_new_aws_resource/fetcher.sh", "aws/detect_new_aws_resource/validate.jq", "aws/_shared/aws.sh", "_lib/status.sh"]:
                dest = tmp / "fetchers" / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text((ROOT / "fetchers" / relative).read_text())
            fake_bin = tmp / "bin"
            fake_bin.mkdir()
            fake = fake_bin / "aws"
            fake.write_text("#!/usr/bin/env python3\nimport json, os, sys\nwith open(os.environ['AWS_FIXTURE']) as f: data = json.load(f)\nprint(json.dumps(data[' '.join(sys.argv[1:3])]))\n")
            fake.chmod(0o755)
            env = dict(os.environ, PATH=str(fake_bin) + os.pathsep + os.environ["PATH"],
                       AWS_FIXTURE=str(tmp / "fixture.json"), EVIDENCE_DIR=str(tmp / "evidence"),
                       AWS_PROFILE="", AWS_DEFAULT_REGION="us-east-1",
                       AWS_DETECT_NEW_RESOURCE_RULE_NAME=NAME, AWS_DETECT_NEW_RESOURCE_TOPIC_NAME=NAME)
            for label, changes, interval, enabled, pattern, target in cases:
                with self.subTest(label=label):
                    data = copy.deepcopy(base)
                    data["events list-rules"][0].update(changes)
                    data["events describe-rule"] = data["events list-rules"][0]
                    if label == "wrong_target":
                        data["events list-targets-by-rule"] = [{"Arn": TOPIC + "-other"}]
                    if label == "missing_topic":
                        data["sns list-topics"] = []
                    if label == "missing_rule":
                        data["events list-rules"] = []
                    # A similarly named rule must never be selected.
                    data["events list-rules"].append({"Name": NAME + "-other", "State": "DISABLED"})
                    (tmp / "fixture.json").write_text(json.dumps(data))
                    result = subprocess.run(["bash", str(tmp / "fetchers/aws/detect_new_aws_resource/fetcher.sh")],
                                            cwd=tmp, env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    output = json.loads(next((tmp / "evidence").glob("*.json")).read_text())
                    checks = output["results"]["validation_results"]
                    self.assertEqual(checks["interval_checks"][NAME]["status"], interval)
                    actual = checks["rule_checks"][NAME]
                    self.assertEqual(actual["enabled"], enabled)
                    self.assertEqual(actual["event_pattern"], pattern)
                    self.assertEqual(actual["sns_target"], target)
                    self.assertEqual(actual["present"], "FAIL" if label == "missing_rule" else "PASS")
                    self.assertNotIn(NAME + "-other", output["results"]["eventbridge"]["rules"])


if __name__ == "__main__":
    unittest.main()
