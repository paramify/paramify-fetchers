# Documentation

Most topics have a **guide** (`*_guide.md`) that walks through one task from
start to finish.

## Run fetchers

- [The `paramify` CLI](cli_guide.md): every command, from manifests to uploads
- [Build a run manifest](run_manifest_guide.md)
- [Give a fetcher its config and secrets](config_injection_guide.md)
- [Read an evidence envelope](envelope_guide.md)
- [Follow one run through the framework](architecture_guide.md)
- [How it runs](architecture.md): the four parts, the evidence envelope and the repo layout
- [Evidence samples](evidence_samples.md): what each fetcher collects, without a run
- [Discovery fetchers](discovery.md): what a set of credentials can see in a platform

**Platform setup.** Most platforms have a guide for their credentials and
permissions:
[AWS](../fetchers/aws/README.md) ·
[Azure](../fetchers/azure/README.md) ·
[GCP](../fetchers/gcp/README.md) ·
[Wiz](../fetchers/wiz/README.md) ·
[Datadog](../fetchers/datadog/README.md) ·
[Okta](../fetchers/okta/README.md) ·
[CrowdStrike](../fetchers/crowdstrike/README.md) ·
[Splunk](../fetchers/splunk/README.md) ·
[SentinelOne](../fetchers/sentinelone/README.md) ·
[KnowBe4](../fetchers/knowbe4/README.md) ·
[GitLab](../fetchers/gitlab/README.md) ·
[Kubernetes](../fetchers/k8s/README.md) ·
[Rippling](../fetchers/rippling/README.md) ·
[Paramify](../fetchers/paramify/README.md) ·
[Checkov](../fetchers/checkov/README.md) ·
[ServiceNow](../fetchers/servicenow/README.md) ·
[Jira](../fetchers/jira/README.md)

## Send results to Paramify

- [Upload a run](uploader_guide.md), and the
  [API key and upload options](../uploaders/paramify_evidence/README.md)
- [Send scan reports to an assessment](pipelines_guide.md), and the
  [scan-report uploader](../uploaders/paramify_issues/README.md)
- [Run an inventory fetcher](inventory_fetchers_guide.md)
- [Sync fetcher scripts to Paramify](../uploaders/paramify_scripts/README.md)

## Validators

- [Write validators with `/suggest-validator`](suggest_validator_guide.md)
- [Write a validator by hand](validators_guide.md)
- [The validator sync stage](../uploaders/paramify_validators/README.md)

## Write fetchers

- [Write a new evidence fetcher](authoring_fetcher_guide.md)
- [Examine a fetcher against the contract](fetcher_contract_guide.md)
- [Onboard a new platform](platform_onboarding_guide.md)
- [Write an issue-report fetcher](issue_report_fetchers_guide.md), and the
  [Wiz pipeline guide](wiz_pipeline_guide.md)

## FedRAMP KSI coverage

- [Fetcher to KSI mapping](ksi_mapping.md): which fetchers cover which KSIs, and
  the gaps
- [Find the fetchers for a KSI](ksi_mapping_guide.md)

## Releases and project

- [Pin a release and upgrade safely](versioning_guide.md)
- [Cut a release](releasing_guide.md)
- [Work in a private copy of this repo](private_mirror_guide.md)
