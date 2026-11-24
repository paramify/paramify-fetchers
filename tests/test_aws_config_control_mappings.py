import importlib.util
import json
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

# The control mappings are vendored data with no generator in the tree, so these
# tests are the only thing standing between a hand-edited mapping file and the
# fetcher. Keep the consistency check below strict.
FETCHER_DIR = (
    Path(__file__).parents[1] / "fetchers" / "aws" / "config_conformance_packs"
)


def test_vendored_mappings_are_nonempty_and_internally_consistent():
    mapping_dir = FETCHER_DIR / "control_mappings"
    for path in sorted(mapping_dir.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        assert document["rule_count"] == len(document["rules"])
        assert document["control_count"] == len(document["controls"])
        assert document["rules"]
        for rule, controls in document["rules"].items():
            for control in controls:
                assert rule in document["controls"][control]["config_rules"]


def test_fetcher_contract_defaults_to_fedramp_low():
    repo = Path(__file__).parents[1]
    if str(repo) not in sys.path:
        sys.path.insert(0, str(repo))

    from framework import api
    from framework.config_loader import discover_fetchers, discover_platforms

    fetchers = discover_fetchers(repo)
    fetcher = fetchers["aws_config_conformance_packs"]
    field = fetcher.config_schema["fedramp_pack"]

    assert field.required is True
    assert field.default == "low"
    assert field.env == "FEDRAMP_PACK"

    legacy_manifest = {
        "run": {
            "output_dir": "./evidence",
            "fetchers": [{"use": "aws_config_conformance_packs"}],
        }
    }
    errors = api.validate(
        legacy_manifest,
        repo,
        fetchers=fetchers,
        platforms=discover_platforms(repo),
    )
    assert errors == []


ACCOUNT = "123456789012"
SUFFIX = "-conformance-pack-qx4bki4j7"


def load_fetcher():
    spec = importlib.util.spec_from_file_location(
        "config_conformance_packs_test_module", FETCHER_DIR / "fetcher.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def evaluation(rule, resource, compliance="NON_COMPLIANT", annotation=None):
    result = {
        "EvaluationResultIdentifier": {
            "EvaluationResultQualifier": {
                "ConfigRuleName": rule,
                "ResourceType": "AWS::IAM::User",
                "ResourceId": resource,
            },
            "OrderingTimestamp": datetime(2026, 1, 1, tzinfo=timezone.utc),
        },
        "ComplianceType": compliance,
        "ResultRecordedTime": datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
        "ConfigRuleInvokedTime": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }
    if annotation:
        result["Annotation"] = annotation
    return result


class FakeConfig:
    """A one-pack AWS Config account. Pages by NextToken at the requested Limit
    (capped by `page_caps`), records every request, and can fail one rule's page."""

    def __init__(self, rules, config_rules, evaluations, page_caps=None, fail=None):
        self.rules = rules
        self.config_rules = config_rules
        self.evaluations = evaluations
        self.page_caps = page_caps or {}
        self.fail = fail
        self.calls = []
        self.lock = threading.Lock()

    def record(self, operation, params):
        with self.lock:
            self.calls.append((operation, dict(params)))

    def page(self, operation, items, params, limit):
        start = int(params.get("NextToken") or 0)
        size = min(limit, self.page_caps.get(operation, limit))
        response = {"items": items[start:start + size], "ResponseMetadata": {"RequestId": "r"}}
        if start + size < len(items):
            response["NextToken"] = str(start + size)
        return response

    def get_caller_identity(self):
        return {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:role/test"}

    def describe_conformance_packs(self, **params):
        self.record("describe_conformance_packs", params)
        return {"ConformancePackDetails": [{"ConformancePackName": "test-pack"}]}

    def describe_conformance_pack_status(self, **params):
        self.record("describe_conformance_pack_status", params)
        return {"ConformancePackStatusDetails": [
            {"ConformancePackName": "test-pack", "ConformancePackState": "CREATE_COMPLETE"}
        ]}

    def describe_conformance_pack_compliance(self, **params):
        self.record("describe_conformance_pack_compliance", params)
        response = self.page("describe_conformance_pack_compliance", self.rules, params, params["Limit"])
        response["ConformancePackName"] = "test-pack"
        response["ConformancePackRuleComplianceList"] = response.pop("items")
        return response

    def describe_config_rules(self, **params):
        self.record("describe_config_rules", params)
        wanted = [rule for rule in self.config_rules if rule["ConfigRuleName"] in params["ConfigRuleNames"]]
        response = self.page("describe_config_rules", wanted, params, 25)
        response["ConfigRules"] = response.pop("items")
        return response

    def get_conformance_pack_compliance_details(self, **params):
        self.record("get_conformance_pack_compliance_details", params)
        (rule,) = params["Filters"]["ConfigRuleNames"]
        if self.fail and self.fail == (rule, params.get("NextToken")):
            raise RuntimeError(
                "An error occurred (AccessDeniedException) when calling the "
                "GetConformancePackComplianceDetails operation: not authorized to perform "
                "config:GetConformancePackComplianceDetails"
            )
        response = self.page(
            "get_conformance_pack_compliance_details", self.evaluations.get(rule, []), params, params["Limit"]
        )
        response["ConformancePackName"] = "test-pack"
        response["ConformancePackRuleEvaluationResults"] = response.pop("items")
        return response

    def get_conformance_pack_compliance_summary(self, **params):
        self.record("get_conformance_pack_compliance_summary", params)
        return {"ConformancePackComplianceSummaryList": [], "ResponseMetadata": {"RequestId": "r"}}


def sample_account(**kwargs):
    rules = [
        {"ConfigRuleName": "access-keys-rotated" + SUFFIX, "ComplianceType": "NON_COMPLIANT", "Controls": []},
        {"ConfigRuleName": "s3-bucket-ssl-requests-only" + SUFFIX, "ComplianceType": "COMPLIANT", "Controls": []},
        {"ConfigRuleName": "custom-rule" + SUFFIX, "ComplianceType": "COMPLIANT", "Controls": []},
    ]
    config_rules = [
        {
            "ConfigRuleName": "access-keys-rotated" + SUFFIX,
            "ConfigRuleArn": f"arn:aws:config:us-east-1:{ACCOUNT}:config-rule/config-rule-1",
            "ConfigRuleId": "config-rule-1",
            "Source": {"Owner": "AWS", "SourceIdentifier": "ACCESS_KEYS_ROTATED"},
        },
        {
            "ConfigRuleName": "s3-bucket-ssl-requests-only" + SUFFIX,
            "ConfigRuleArn": f"arn:aws:config:us-east-1:{ACCOUNT}:config-rule/config-rule-2",
            "ConfigRuleId": "config-rule-2",
            "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_SSL_REQUESTS_ONLY"},
        },
        {
            "ConfigRuleName": "custom-rule" + SUFFIX,
            "ConfigRuleArn": f"arn:aws:config:us-east-1:{ACCOUNT}:config-rule/config-rule-3",
            "ConfigRuleId": "config-rule-3",
            "Source": {
                "Owner": "CUSTOM_LAMBDA",
                "SourceIdentifier": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:custom-rule",
            },
        },
    ]
    evaluations = {"access-keys-rotated" + SUFFIX: [
        evaluation("access-keys-rotated" + SUFFIX, "alice", annotation="key too old")
    ]}
    return FakeConfig(rules, config_rules, evaluations, **kwargs)


def run_fetcher(client, fedramp_pack="moderate"):
    """(exit code, evidence or None, status file or None) for one run against `client`."""
    fetcher = load_fetcher()
    fetcher.session_and_client = lambda: (client, client)
    import os

    saved = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="paramify-conformance-packs-") as directory:
        root = Path(directory)
        try:
            for key in [k for k in os.environ if k.startswith("AWS_")]:
                del os.environ[key]
            os.environ.update({
                "FEDRAMP_PACK": fedramp_pack,
                "AWS_DEFAULT_REGION": "us-east-1",
                "EVIDENCE_DIR": str(root / "evidence"),
                "FETCHER_STATUS_FILE": str(root / "status.json"),
            })
            code = fetcher.main()
        finally:
            os.environ.clear()
            os.environ.update(saved)
        output = root / "evidence" / "aws_config_conformance_packs_ambient_us-east-1.json"
        status = root / "status.json"
        return (
            code,
            json.loads(output.read_text(encoding="utf-8")) if output.exists() else None,
            json.loads(status.read_text(encoding="utf-8")) if status.exists() else None,
        )


def test_fetcher_maps_rules_findings_and_control_compliance():
    code, result, _ = run_fetcher(sample_account())
    assert code == 0
    pack = result["results"]["test-pack"]
    access_keys = next(
        rule for rule in pack["control_mapping"]["rules"]
        if rule["config_rule_name"] == "access-keys-rotated-conformance-pack-qx4bki4j7"
    )
    assert access_keys["source_identifier"] == "ACCESS_KEYS_ROTATED"
    assert "AC-2(1)" in access_keys["fedramp_controls"]
    assert "AC-3(15)" in access_keys["nist_800_53_rev_5_controls"]
    enriched_access_keys = next(
        rule for rule in pack["rule_compliance"]
        if rule["ConfigRuleName"] == "access-keys-rotated-conformance-pack-qx4bki4j7"
    )
    assert enriched_access_keys["Source"]["SourceIdentifier"] == "ACCESS_KEYS_ROTATED"
    assert enriched_access_keys["ServiceControls"] == []
    assert "AC-2(1)" in enriched_access_keys["FedRAMPControls"]
    assert "AC-3(15)" in enriched_access_keys["NIST80053Rev5Controls"]
    assert set(enriched_access_keys["Controls"]) == (
        set(enriched_access_keys["ServiceControls"])
        | set(enriched_access_keys["FedRAMPControls"])
        | set(enriched_access_keys["NIST80053Rev5Controls"])
    )
    assert pack["aws_rule_compliance"][0]["Controls"] == []
    custom_rule = next(
        rule for rule in pack["control_mapping"]["rules"]
        if rule["config_rule_name"] == "custom-rule-conformance-pack-qx4bki4j7"
    )
    assert custom_rule["mapped"] is False
    assert custom_rule["fedramp_controls"] == []
    assert custom_rule["nist_800_53_rev_5_controls"] == []
    enriched_custom_rule = next(
        rule for rule in pack["rule_compliance"]
        if rule["ConfigRuleName"] == "custom-rule-conformance-pack-qx4bki4j7"
    )
    assert enriched_custom_rule["Controls"] == []
    assert pack["non_compliant_findings"][0]["fedramp_controls"]
    assert pack["template_match"].get("comparison_key") == "Source.SourceIdentifier", pack["template_match"]
    assert pack["template_match"]["matching_rule_count"] == 2
    assert pack["template_match"]["deployed_rule_count"] == 3
    assert any(
        control["rule_aggregate_compliance_type"] == "NON_COMPLIANT"
        for control in pack["control_mapping"]["fedramp"]["controls"]
    )
    assert result["summary"]["test-pack"]["fedramp_controls_with_non_compliant_rules"] > 0
    assert result["summary"]["test-pack"]["nist_800_53_controls_with_non_compliant_rules"] > 0


def test_fetcher_writes_aws_timestamps_and_no_response_metadata():
    _, result, _ = run_fetcher(sample_account())
    pack = result["results"]["test-pack"]
    (finding,) = pack["non_compliant_findings"]
    assert finding["ordering_timestamp"] == "2026-01-01T00:00:00+00:00"
    assert finding["result_recorded_time"] == "2026-01-01T00:00:01+00:00"
    assert finding["annotation"] == "key too old"
    assert pack["aws_compliance_summary"] == {"ConformancePackComplianceSummaryList": []}
    assert "ResponseMetadata" not in json.dumps(result)


def test_fetcher_follows_every_page_at_the_api_maximum():
    client = sample_account(page_caps={
        "describe_conformance_pack_compliance": 2,
        "describe_config_rules": 1,
        "get_conformance_pack_compliance_details": 100,
    })
    rule = "access-keys-rotated" + SUFFIX
    client.evaluations[rule] = [evaluation(rule, f"user-{i}") for i in range(250)]
    code, result, _ = run_fetcher(client)
    assert code == 0
    pack = result["results"]["test-pack"]
    assert pack["rule_count"] == 3
    assert len(pack["config_rule_metadata"]) == 3
    assert pack["resource_evaluation_count"] == 250
    assert [e["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"]
            for e in pack["resource_evaluations"]] == [f"user-{i}" for i in range(250)]
    limits = {(op, params.get("Limit")) for op, params in client.calls if "Limit" in params}
    assert limits == {
        ("describe_conformance_pack_compliance", 1000),
        ("get_conformance_pack_compliance_details", 100),
    }
    detail_calls = [p for op, p in client.calls if op == "get_conformance_pack_compliance_details"]
    # One call per rule, plus two more pages for the rule with 250 evaluations.
    assert len(detail_calls) == 5


def test_fetcher_keeps_rule_order_whatever_order_the_workers_finish():
    client = sample_account()
    names = [f"rule-{i:02d}" + SUFFIX for i in range(20)]
    client.rules = [{"ConfigRuleName": n, "ComplianceType": "NON_COMPLIANT", "Controls": []} for n in reversed(names)]
    client.config_rules = []
    client.evaluations = {n: [evaluation(n, n)] for n in names}
    _, result, _ = run_fetcher(client)
    pack = result["results"]["test-pack"]
    assert [f["config_rule_name"] for f in pack["non_compliant_findings"]] == names


def test_fetcher_reports_a_failed_rule_page_and_keeps_the_pages_it_read():
    rule = "access-keys-rotated" + SUFFIX
    client = sample_account(page_caps={"get_conformance_pack_compliance_details": 100}, fail=(rule, "100"))
    client.evaluations[rule] = [evaluation(rule, f"user-{i}") for i in range(150)]
    code, result, status = run_fetcher(client)
    assert code == 1
    assert result["results"]["test-pack"]["resource_evaluation_count"] == 100
    assert status["code"] == "not_authorized"
    assert f"get-conformance-pack-compliance-details (test-pack rule {rule} page 2) failed" in status["error"]


def test_fetcher_fails_on_a_repeated_conformance_pack_token():
    client = sample_account()

    def describe_conformance_packs(**params):
        client.record("describe_conformance_packs", params)
        return {"ConformancePackDetails": [{"ConformancePackName": "test-pack"}], "NextToken": "same"}

    client.describe_conformance_packs = describe_conformance_packs
    code, _, status = run_fetcher(client)
    assert code == 1
    assert "describe-conformance-packs returned a repeated NextToken" in status["error"]


def test_fetcher_rejects_an_unknown_fedramp_pack():
    code, result, status = run_fetcher(sample_account(), fedramp_pack="high")
    assert code == 2
    assert result is None
    assert status["code"] == "bad_config"
    assert "FEDRAMP_PACK must be either low or moderate" in status["error"]

if __name__ == "__main__":
    test_vendored_mappings_are_nonempty_and_internally_consistent()
    test_fetcher_contract_defaults_to_fedramp_low()
    test_fetcher_maps_rules_findings_and_control_compliance()
    print("control mapping tests passed")
