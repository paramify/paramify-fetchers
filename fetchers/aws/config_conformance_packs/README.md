# AWS Config Conformance Packs

This fetcher collects AWS Config conformance pack deployment status, rule-level
compliance, and resource-level evaluation results. It also maps deployed Config
rules to controls from:

- the selected FedRAMP Low or Moderate baseline; and
- NIST SP 800-53 Revision 5.

The output is evidence about automated AWS Config checks. It does not establish
that an account, system, or individual control is compliant with FedRAMP or NIST.

## Configuration

| Variable | Required | Description |
|---|---:|---|
| `FEDRAMP_PACK` | No | Reference baseline and mapping to use: `low` (default) or `moderate` |
| `AWS_PROFILE` | No | AWS CLI profile; when omitted, the ambient credential chain is used |
| `AWS_DEFAULT_REGION` | No | AWS region; when omitted, AWS CLI configuration determines the region |
| `EVIDENCE_DIR` | No | Output directory; defaults to `./evidence` |

Example:

```bash
FEDRAMP_PACK=moderate \
AWS_PROFILE=production-audit \
AWS_DEFAULT_REGION=us-east-1 \
EVIDENCE_DIR=./evidence \
./fetchers/aws/config_conformance_packs/fetcher.sh
```

The manifest schema exposes `FEDRAMP_PACK` as the `fedramp_pack` configuration
value. It defaults to `low`, preserving manifests created before this option was
introduced. AWS profile and region can be supplied per target for multi-account
or multi-region collection.

Example Paramify manifest entry using the FedRAMP Moderate baseline for the
`va-readonly` profile in `us-east-2`:

```yaml
  - use: aws_config_conformance_packs
    config:
      fedramp_pack: moderate
    targets:
    - profile: va-readonly
      region: us-east-2
```

## Requirements and IAM permissions

Runtime tools:

- AWS CLI
- `jq`
- `awk`, `sort`, and `comm`

The AWS identity needs read access to these actions:

- `sts:GetCallerIdentity`
- `config:DescribeConformancePacks`
- `config:DescribeConformancePackStatus`
- `config:DescribeConformancePackCompliance`
- `config:DescribeConfigRules`
- `config:GetConformancePackComplianceSummary`
- `config:GetConformancePackComplianceDetails`

## Collection and pagination

For every conformance pack, the fetcher:

1. Retrieves deployment status.
2. Explicitly follows `NextToken` for `DescribeConformancePackCompliance` until
   all rules have been collected.
3. Resolves generated conformance-pack rule names to stable
   `Source.SourceIdentifier` values with paginated `DescribeConfigRules` calls
   in batches of at most 25 names.
4. Requests resource evaluations separately for every rule and follows that
   rule's `NextToken` chain until exhausted.
5. Collects the AWS compliance summary.
6. Compares deployed rule source identifiers with the selected vendored
   FedRAMP template.
7. Enriches rules and non-compliant resource findings with FedRAMP and NIST
   control identifiers.

Explicit API pagination is used instead of relying on AWS CLI auto-pagination.
A repeated token is treated as a collection failure to prevent an infinite loop.

## Control mappings

The runtime fetcher is network-independent apart from AWS API calls. Control
mappings are vendored under [`control_mappings/`](control_mappings/) and are
generated from the official AWS Config mapping tables:

- [FedRAMP Low](https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-fedramp-low.html)
- [FedRAMP Moderate](https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-fedramp-moderate.html)
- [NIST SP 800-53 Revision 5](https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-nist-800-53_rev_5.html)

Current vendored coverage:

| Framework | Config rules | Controls |
|---|---:|---:|
| FedRAMP Low | 116 | 32 |
| FedRAMP Moderate | 128 | 71 |
| NIST SP 800-53 Rev. 5 | 128 | 113 |

Mappings are matched primarily by `Source.SourceIdentifier`, because AWS appends
generated suffixes such as `-conformance-pack-qx4bki4j7` to deployed
`ConfigRuleName` values. Managed identifiers such as `ACCESS_KEYS_ROTATED` are
normalized to the AWS documentation rule name. The base `ConfigRuleName` and
explicit aliases are used only as fallback. Custom rules and rules without an
AWS-published mapping are retained with empty control arrays and `mapped: false`;
the fetcher never invents a control relationship.

To refresh the vendored mappings:

```bash
python fetchers/aws/config_conformance_packs/sync_control_mappings.py
```

The sync script parses the AWS tables, builds both rule-to-control and
control-to-rule indexes, validates that the tables are non-empty, and writes
deterministic JSON files.

## Evidence output

The output uses per-target naming:

```text
aws_config_conformance_packs_<profile-or-ambient>_<region>.json
```

Top-level fields include:

- `metadata`: AWS account, identity, profile, region, and collection time.
- `selected_fedramp_pack`: `low` or `moderate`.
- `reference_template`: selected template name, checksum, source, and rule count.
- `control_mapping_sources`: framework provenance, mapping size, and disclaimer.
- `results`: detailed evidence keyed by conformance pack name.
- `summary`: compact rule and mapped-control counts keyed by pack name.

Each `results.<pack>.control_mapping.rules[]` entry has this shape:

```json
{
  "config_rule_name": "access-keys-rotated-conformance-pack-qx4bki4j7",
  "source_identifier": "ACCESS_KEYS_ROTATED",
  "compliance_type": "NON_COMPLIANT",
  "service_controls": [],
  "fedramp_controls": ["AC-2(1)", "AC-2(f)", "AC-2(j)"],
  "nist_800_53_rev_5_controls": ["AC-3(15)"],
  "mapped": true
}
```

`rule_compliance` retains the AWS rule fields but enriches every rule with:

- `Source`: metadata returned by `DescribeConfigRules`, including the stable
  `SourceIdentifier` used for mapping;
- `ServiceControls`: the original `Controls` array returned by AWS;
- `FedRAMPControls`: controls from the selected FedRAMP mapping;
- `NIST80053Rev5Controls`: controls from the NIST SP 800-53 Rev. 5 mapping; and
- `Controls`: the unique union of all three arrays.

The unmodified AWS rule response remains available in `aws_rule_compliance`, and
raw resource evaluations remain available in `resource_evaluations`.
`non_compliant_findings` contains a smaller resource-focused representation and
includes both framework-specific control arrays.

### Control-level aggregation

`control_mapping.fedramp.controls` and
`control_mapping.nist_800_53.controls` provide a reverse view from each control
to the deployed mapped rules. For example:

```json
{
  "control_id": "AC-2(1)",
  "description": "...",
  "rule_aggregate_compliance_type": "NON_COMPLIANT",
  "config_rules": [
    {
      "config_rule_name": "access-keys-rotated-conformance-pack-qx4bki4j7",
      "compliance_type": "NON_COMPLIANT"
    }
  ]
}
```

The aggregation basis is `DEPLOYED_MAPPED_CONFIG_RULES`. Its precedence is:

1. `NON_COMPLIANT` if any mapped deployed rule is non-compliant.
2. `INSUFFICIENT_DATA` if none are non-compliant and at least one lacks data.
3. `COMPLIANT` if every mapped deployed rule is compliant.
4. `UNKNOWN` otherwise.

This value is deliberately named `rule_aggregate_compliance_type`: it describes
the Config rules associated with a control, not the overall compliance status of
the control. Manual, procedural, and technical evidence outside AWS Config may
still be required.

## Reference templates

The selected template is used for deployed-rule coverage comparison:

- [`Operational-Best-Practices-for-FedRAMP-Low.yaml`](Operational-Best-Practices-for-FedRAMP-Low.yaml)
- [`Operational-Best-Practices-for-FedRAMP-Moderate.yaml`](Operational-Best-Practices-for-FedRAMP-Moderate.yaml)

The output reports matching, missing, and extra rules. Comparison uses
`Source.SourceIdentifier`, while the arrays contain readable reference rule
names. Template coverage and control-mapping coverage are separate concepts: a
rule can be present in a FedRAMP sample template without having an explicit
mapping row in the current AWS documentation table.

## Validation

Run the focused regression tests with pytest:

```bash
python -m pytest tests/test_aws_config_control_mappings.py -q
```

The test module can also run standalone when pytest is unavailable:

```bash
python tests/test_aws_config_control_mappings.py
```

The standalone integration test requires `bash` and `jq`. If `jq` is not on
`PATH`, provide its executable through `JQ_BIN`.
