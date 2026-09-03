import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT = (
    Path(__file__).parents[1]
    / "fetchers"
    / "aws"
    / "config_conformance_packs"
    / "sync_control_mappings.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("sync_control_mappings", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_parse_mapping_builds_rule_and_control_indexes():
    module = _load_module()
    html = """
    <table>
      <tr><th>Control ID</th><th>Control Description</th><th>AWS Config Rule</th><th>Guidance</th></tr>
      <tr><td>AC-2 (1)</td><td>Account management</td><td><a>iam-rule</a></td><td>One</td></tr>
      <tr><td>AC-3</td><td>Access enforcement</td><td><a>iam-rule</a></td><td>Two</td></tr>
      <tr><td>AC-2 (1)</td><td>Account management</td><td><a>second-rule</a></td><td>Three</td></tr>
    </table>
    """

    result = module.parse_mapping(html, "test", "Test", "https://example.test")

    assert result["rules"] == {
        "iam-rule": ["AC-2(1)", "AC-3"],
        "second-rule": ["AC-2(1)"],
    }
    assert result["controls"]["AC-2(1)"]["config_rules"] == ["iam-rule", "second-rule"]
    assert result["rule_count"] == 2
    assert result["control_count"] == 2


def test_parse_mapping_includes_only_aliases_available_in_the_source():
    module = _load_module()
    html = """
    <table>
      <tr><th>Control ID</th><th>Control Description</th><th>AWS Config Rule</th><th>Guidance</th></tr>
      <tr><td>AC-2</td><td>Account management</td><td>cloudtrail-enabled</td><td>One</td></tr>
    </table>
    """
    result = module.parse_mapping(html, "test", "Test", "https://example.test")
    assert result["aliases"] == {"cloud-trail-enabled": "cloudtrail-enabled"}


def test_vendored_mappings_are_nonempty_and_internally_consistent():
    import json

    mapping_dir = SCRIPT.parent / "control_mappings"
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
    from framework.config_loader import discover_fetchers
    from framework.config_loader import discover_platforms

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


def test_fetcher_does_not_require_bash_mapfile():
    fetcher = SCRIPT.parent / "fetcher.sh"
    source = fetcher.read_text(encoding="utf-8")

    assert "mapfile -t" not in source


def test_fetcher_maps_rules_findings_and_control_compliance():
    import json

    bash = shutil.which("bash")
    jq = os.environ.get("JQ_BIN") or shutil.which("jq")
    if not bash or not jq:
        import pytest

        pytest.skip("bash and jq are required for the fetcher integration test")

    repo = Path(__file__).parents[1]
    fetcher = repo / "fetchers" / "aws" / "config_conformance_packs" / "fetcher.sh"
    with tempfile.TemporaryDirectory(prefix="paramify-control-mapping-") as directory:
        root = Path(directory)
        bin_dir = root / "bin"
        evidence_dir = root / "evidence"
        bin_dir.mkdir()
        evidence_dir.mkdir()
        jq_link = bin_dir / ("jq.exe" if os.name == "nt" else "jq")
        try:
            jq_link.symlink_to(Path(jq).resolve())
        except OSError:
            shutil.copy2(jq, jq_link)

        aws = bin_dir / "aws"
        aws.write_text(
            """#!/usr/bin/env bash
case "$1 $2" in
  "sts get-caller-identity")
    echo '{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:role/test"}' ;;
  "configservice describe-conformance-packs")
    echo '{"ConformancePackDetails":[{"ConformancePackName":"test-pack"}]}' ;;
  "configservice describe-conformance-pack-status")
    echo '[{"ConformancePackName":"test-pack","ConformancePackState":"CREATE_COMPLETE"}]' ;;
  "configservice describe-conformance-pack-compliance")
    echo '{"ConformancePackName":"test-pack","ConformancePackRuleComplianceList":[{"ConfigRuleName":"access-keys-rotated-conformance-pack-qx4bki4j7","ComplianceType":"NON_COMPLIANT","Controls":[]},{"ConfigRuleName":"s3-bucket-ssl-requests-only-conformance-pack-qx4bki4j7","ComplianceType":"COMPLIANT","Controls":[]},{"ConfigRuleName":"custom-rule-conformance-pack-qx4bki4j7","ComplianceType":"COMPLIANT","Controls":[]}]}' ;;
  "configservice describe-config-rules")
    echo '{"ConfigRules":[{"ConfigRuleName":"access-keys-rotated-conformance-pack-qx4bki4j7","ConfigRuleArn":"arn:aws:config:us-east-1:123456789012:config-rule/config-rule-1","ConfigRuleId":"config-rule-1","Source":{"Owner":"AWS","SourceIdentifier":"ACCESS_KEYS_ROTATED"}},{"ConfigRuleName":"s3-bucket-ssl-requests-only-conformance-pack-qx4bki4j7","ConfigRuleArn":"arn:aws:config:us-east-1:123456789012:config-rule/config-rule-2","ConfigRuleId":"config-rule-2","Source":{"Owner":"AWS","SourceIdentifier":"S3_BUCKET_SSL_REQUESTS_ONLY"}},{"ConfigRuleName":"custom-rule-conformance-pack-qx4bki4j7","ConfigRuleArn":"arn:aws:config:us-east-1:123456789012:config-rule/config-rule-3","ConfigRuleId":"config-rule-3","Source":{"Owner":"CUSTOM_LAMBDA","SourceIdentifier":"arn:aws:lambda:us-east-1:123456789012:function:custom-rule"}}]}' ;;
  "configservice get-conformance-pack-compliance-details")
    input=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--cli-input-json" ]; then input="$2"; break; fi
      shift
    done
    if printf '%s' "$input" | grep -q 'access-keys-rotated'; then
      echo '{"ConformancePackName":"test-pack","ConformancePackRuleEvaluationResults":[{"EvaluationResultIdentifier":{"EvaluationResultQualifier":{"ConfigRuleName":"access-keys-rotated-conformance-pack-qx4bki4j7","ResourceType":"AWS::IAM::User","ResourceId":"alice"},"OrderingTimestamp":"2026-01-01T00:00:00Z"},"ComplianceType":"NON_COMPLIANT","Annotation":"key too old","ResultRecordedTime":"2026-01-01T00:00:01Z","ConfigRuleInvokedTime":"2026-01-01T00:00:00Z"}]}'
    else
      echo '{"ConformancePackName":"test-pack","ConformancePackRuleEvaluationResults":[]}'
    fi ;;
  "configservice get-conformance-pack-compliance-summary")
    echo '{"ConformancePackComplianceSummaryList":[]}' ;;
  *) echo "unexpected aws call: $*" >&2; exit 2 ;;
esac
""",
            encoding="utf-8",
        )
        aws.chmod(0o755)

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{bin_dir}{os.pathsep}{env['PATH']}",
                "FEDRAMP_PACK": "moderate",
                "AWS_DEFAULT_REGION": "us-east-1",
                "EVIDENCE_DIR": str(evidence_dir),
            }
        )
        subprocess.run([bash, str(fetcher)], cwd=repo, env=env, check=True)

        output = evidence_dir / "aws_config_conformance_packs_ambient_us-east-1.json"
        result = json.loads(output.read_text(encoding="utf-8"))
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


if __name__ == "__main__":
    test_parse_mapping_builds_rule_and_control_indexes()
    test_parse_mapping_includes_only_aliases_available_in_the_source()
    test_vendored_mappings_are_nonempty_and_internally_consistent()
    test_fetcher_contract_defaults_to_fedramp_low()
    test_fetcher_does_not_require_bash_mapfile()
    test_fetcher_maps_rules_findings_and_control_compliance()
    print("control mapping tests passed")
