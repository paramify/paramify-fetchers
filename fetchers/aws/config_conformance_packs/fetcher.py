#!/usr/bin/env python3
"""Lists AWS Config conformance packs and collects deployment status, rule-level
compliance, and resource-level evaluation results. FEDRAMP_PACK (low|moderate)
selects the bundled reference conformance pack used for rule-set comparison.

Output: $EVIDENCE_DIR/aws_config_conformance_packs_<profile|ambient>[_<region>].json
Optional env (else the boto3 ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION

One process and one Config client for the whole target. Resource evaluations
are read one rule at a time (each rule's NextToken chain is independent), so
the rules of a pack are read on a small thread pool.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_lib"))
from fetcher_status import report_failure  # noqa: E402

NAME = "aws_config_conformance_packs"
FETCHER_DIR = Path(__file__).resolve().parent
RULE_WORKERS = 8
# DescribeConfigRules accepts at most 25 names per call.
CONFIG_RULES_BATCH = 25
# The API maximums.
RULE_COMPLIANCE_PAGE = 1000
EVALUATIONS_PAGE = 100

REFERENCES = {
    "low": {
        "key": "fedramp_low",
        "label": "Operational Best Practices for FedRAMP (Low)",
        "template": "Operational-Best-Practices-for-FedRAMP-Low.yaml",
        "mapping": "control_mappings/fedramp_low.json",
        "source_url": "https://github.com/awslabs/aws-config-rules/blob/master/aws-config-conformance-packs/Operational-Best-Practices-for-FedRAMP-Low.yaml",
    },
    "moderate": {
        "key": "fedramp_moderate",
        "label": "Operational Best Practices for FedRAMP (Moderate)",
        "template": "Operational-Best-Practices-for-FedRAMP-Moderate.yaml",
        "mapping": "control_mappings/fedramp_moderate.json",
        "source_url": "https://github.com/awslabs/aws-config-rules/blob/master/aws-config-conformance-packs/Operational-Best-Practices-for-FedRAMP.yaml",
    },
}
NIST_800_53_MAPPING = "control_mappings/nist_800_53_rev_5.json"
AGGREGATION_BASIS = "DEPLOYED_MAPPED_CONFIG_RULES"

# Same order and patterns as aws_classify_code in _shared/aws.sh: the most
# specific cause wins, whichever call failed first.
ERROR_CODES = (
    (r"ExpiredToken|InvalidClientTokenId|UnrecognizedClientException|SignatureDoesNotMatch|Unable to locate credentials"
     r"|The security token included in the request is (expired|invalid)|NoCredentialProviders|NoCredentialsError"
     r"|sso session .* is expired|Your session has expired|Token has expired", "auth_failed"),
    (r"AccessDenied|UnauthorizedOperation|not authorized to perform|AuthorizationError|explicit deny|\(403\)",
     "not_authorized"),
    (r"Throttling|ThrottlingException|TooManyRequests|RequestLimitExceeded|SlowDown|Rate exceeded|\(429\)",
     "rate_limited"),
    (r"Could not connect to the endpoint URL|EndpointConnectionError|ConnectTimeoutError|ReadTimeoutError"
     r"|Connection was closed|Name or service not known|[Tt]emporary failure in name resolution|\(50[34]\)",
     "target_unreachable"),
    (r"InvalidParameterValue|ValidationError|ValidationException|Invalid region|Invalid( |-)?ARN|InvalidInput"
     r"|NoRegionError|ProfileNotFound", "bad_config"),
)

CONFIG_RULE_NAME = re.compile(r"^\s+ConfigRuleName:\s*")
SOURCE_IDENTIFIER = re.compile(r"^\s+SourceIdentifier:\s*")
MANAGED_SOURCE = re.compile(r"^[A-Z0-9_]+$")
PACK_SUFFIX = re.compile(r"-conformance-pack-[a-z0-9-]+$")


def classify(errors):
    text = "\n".join(errors)
    for pattern, code in ERROR_CODES:
        if re.search(pattern, text, re.I):
            return code
    return "partial_failure"


def plain(value):
    """boto3 values as the JSON the AWS CLI prints: timestamps become ISO 8601, ResponseMetadata is dropped."""
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items() if k != "ResponseMetadata"}
    if isinstance(value, list):
        return [plain(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def describe(exc):
    """One line of error text, led by the exception type so classify() sees botocore's NoRegionError and the like."""
    return " ".join(f"{type(exc).__name__}: {exc}".split())[:500]


# --------------------------------------------------------------------------- #
# Reference template and control mappings
# --------------------------------------------------------------------------- #


def reference_rules(template_text):
    """(sorted rule names, SourceIdentifier → rule name) from an AWS conformance pack template.

    No YAML parser is needed: ConfigRuleName and SourceIdentifier are stable
    scalars in AWS's templates, and each rule's SourceIdentifier follows its name.
    """
    names, lookup, rule = set(), {}, ""
    for line in template_text.splitlines():
        line = line.rstrip("\r")
        if CONFIG_RULE_NAME.match(line):
            rule = CONFIG_RULE_NAME.sub("", line, count=1)
            names.add(rule)
        if SOURCE_IDENTIFIER.match(line):
            source = SOURCE_IDENTIFIER.sub("", line, count=1)
            if rule:
                lookup[source] = rule
            rule = ""
    return sorted(names), lookup


def source_rule_name(source_identifier):
    """A managed rule's SourceIdentifier as its template rule name: ACCESS_KEYS_ROTATED → access-keys-rotated."""
    source = source_identifier or ""
    return source.lower().replace("_", "-") if MANAGED_SOURCE.match(source) else ""


def controls_by_name(mapping, name):
    rules = mapping.get("rules") or {}
    found = rules.get(name)
    if found is None:
        found = rules.get((mapping.get("aliases") or {}).get(name) or name)
    return found


def mapped_controls(mapping, rule_name, source_identifier):
    """Controls for a deployed rule: by its managed SourceIdentifier, else by its name without the pack suffix."""
    found = controls_by_name(mapping, source_rule_name(source_identifier))
    if found is None:
        found = controls_by_name(mapping, PACK_SUFFIX.sub("", rule_name or "", count=1))
    return found if found is not None else []


def aggregate_compliance(mapped_rules):
    types = [rule["compliance_type"] for rule in mapped_rules]
    if "NON_COMPLIANT" in types:
        return "NON_COMPLIANT"
    if "INSUFFICIENT_DATA" in types:
        return "INSUFFICIENT_DATA"
    if all(t == "COMPLIANT" for t in types):
        return "COMPLIANT"
    return "UNKNOWN"


def control_compliance(mapping, rule_control_mapping, field):
    controls = []
    for control_id, control in (mapping.get("controls") or {}).items():
        mapped_rules = [
            {"config_rule_name": rule["config_rule_name"], "compliance_type": rule["compliance_type"]}
            for rule in rule_control_mapping
            if control_id in rule[field]
        ]
        if mapped_rules:
            controls.append({
                "control_id": control_id,
                "description": control.get("description"),
                "rule_aggregate_compliance_type": aggregate_compliance(mapped_rules),
                "config_rules": mapped_rules,
            })
    return controls


def mapping_source(mapping):
    return {key: mapping.get(key) for key in
            ("framework", "title", "source_url", "rule_count", "control_count", "disclaimer")}


def unique(values):
    """jq's unique: sorted, without duplicates."""
    return sorted(set(values))


def as_number(text):
    """A "%.2f" string as jq's tonumber prints it: 100.00 → 100, 66.67 → 66.67."""
    value = float(text)
    return int(value) if value.is_integer() else value


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #


class Collector:
    def __init__(self, client):
        self.client = client
        # (label, error text), in collection order: resource-evaluation failures
        # follow rule-name order, not the order the workers finish.
        self.failures = []

    def fail(self, label, exc=None, into=None):
        (self.failures if into is None else into).append((label, describe(exc) if exc is not None else ""))

    def pages(self, operation, label, into=None, **params):
        """Every response page; a failed or invalid page is recorded and ends the chain.

        Pages already read are kept, as the shell fetcher kept them.
        """
        seen = set()
        page = 1
        while True:
            try:
                response = getattr(self.client, operation)(**params)
            except Exception as exc:
                self.fail(f"aws configservice {label} page {page}) failed", exc, into)
                return
            if not isinstance(response, dict):
                self.fail(f"invalid {label} page {page})", into=into)
                return
            yield response
            token = response.get("NextToken")
            if not token:
                return
            if token in seen:
                self.fail(f"{label}) returned a repeated NextToken", into=into)
                return
            seen.add(token)
            params["NextToken"] = token
            page += 1

    def pack_names(self):
        names = []
        params = {}
        seen = set()
        try:
            while True:
                response = self.client.describe_conformance_packs(**params)
                names.extend(
                    pack.get("ConformancePackName")
                    for pack in response.get("ConformancePackDetails") or []
                    if pack.get("ConformancePackName")
                )
                token = response.get("NextToken")
                if not token:
                    break
                if token in seen:
                    self.fail("describe-conformance-packs returned a repeated NextToken")
                    break
                seen.add(token)
                params["NextToken"] = token
        except Exception as exc:
            self.fail("aws configservice describe-conformance-packs failed", exc)
            return []
        return names

    def pack_status(self, pack):
        try:
            response = self.client.describe_conformance_pack_status(ConformancePackNames=[pack])
        except Exception as exc:
            self.fail(f"aws configservice describe-conformance-pack-status ({pack}) failed", exc)
            return []
        return plain(response.get("ConformancePackStatusDetails") or [])

    def rule_compliance(self, pack):
        """Rule-level compliance, the authoritative source for COMPLIANT / NON_COMPLIANT / INSUFFICIENT_DATA."""
        document = {"ConformancePackName": pack, "ConformancePackRuleComplianceList": []}
        for page in self.pages("describe_conformance_pack_compliance",
                               f"describe-conformance-pack-compliance ({pack}",
                               ConformancePackName=pack, Limit=RULE_COMPLIANCE_PAGE):
            document["ConformancePackName"] = page.get("ConformancePackName") or document["ConformancePackName"]
            document["ConformancePackRuleComplianceList"] += plain(page.get("ConformancePackRuleComplianceList") or [])
        return document

    def config_rules(self, rule_names):
        """Deployed rules' metadata: conformance pack rules carry generated name suffixes, and
        Source.SourceIdentifier is the stable value to match them on."""
        rules = []
        for offset in range(0, len(rule_names), CONFIG_RULES_BATCH):
            batch = rule_names[offset:offset + CONFIG_RULES_BATCH]
            for page in self.pages("describe_config_rules",
                                   f"describe-config-rules (batch {offset // CONFIG_RULES_BATCH + 1}",
                                   ConfigRuleNames=batch):
                rules += plain(page.get("ConfigRules") or [])
        return {"ConfigRules": rules}

    def rule_evaluations(self, pack, rule):
        failures, results = [], []
        for page in self.pages("get_conformance_pack_compliance_details",
                               f"get-conformance-pack-compliance-details ({pack} rule {rule}", failures,
                               ConformancePackName=pack, Filters={"ConfigRuleNames": [rule]},
                               Limit=EVALUATIONS_PAGE):
            results += plain(page.get("ConformancePackRuleEvaluationResults") or [])
        return results, failures

    def resource_evaluations(self, pack, rule_names):
        """Resource-level evaluations, one NextToken chain per rule, read RULE_WORKERS rules at a time."""
        if not rule_names:
            return []
        with ThreadPoolExecutor(max_workers=min(RULE_WORKERS, len(rule_names))) as pool:
            # map keeps rule-name order.
            read = list(pool.map(lambda rule: self.rule_evaluations(pack, rule), rule_names))
        evaluations = []
        for results, failures in read:
            evaluations += results
            self.failures.extend(failures)
        return evaluations

    def compliance_summary(self, pack):
        summaries = []
        for page in self.pages("get_conformance_pack_compliance_summary",
                               f"get-conformance-pack-compliance-summary ({pack}",
                               ConformancePackNames=[pack]):
            summaries += plain(page.get("ConformancePackComplianceSummaryList") or [])
        return {"ConformancePackComplianceSummaryList": summaries}


def template_match(reference, deployed_rule_names):
    reference_names = set(reference["rule_names"])
    deployed = set(deployed_rule_names)
    missing = sorted(reference_names - deployed)
    extra = sorted(deployed - reference_names)
    overlap = len(deployed & reference_names)
    template_count = len(reference_names)
    coverage = f"{overlap / template_count * 100:.2f}" if template_count > 0 else "0.00"
    return {
        "reference": reference["key"],
        "comparison_key": "Source.SourceIdentifier",
        "deployed_rule_count": len(deployed),
        "template_rule_count": template_count,
        "matching_rule_count": overlap,
        "coverage_percent": as_number(coverage),
        "missing_template_rules_count": len(missing),
        "extra_deployed_rules_count": len(extra),
        "missing_template_rules": missing,
        "extra_deployed_rules": extra,
    }


def pack_result(reference, fedramp_mapping, nist_mapping, status, rules_doc, config_rules_doc, evaluations,
                summary_doc):
    rules = rules_doc["ConformancePackRuleComplianceList"]
    config_rule_metadata = config_rules_doc["ConfigRules"]
    config_rule_index = {rule.get("ConfigRuleName"): rule for rule in config_rule_metadata}

    def source_of(rule_name):
        return ((config_rule_index.get(rule_name) or {}).get("Source") or {}).get("SourceIdentifier")

    state = (status[0].get("ConformancePackState") if status else None) or "UNKNOWN"
    counts = {t: sum(1 for rule in rules if rule.get("ComplianceType") == t)
              for t in ("COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_DATA")}

    enriched_rules = []
    for rule in rules:
        metadata = config_rule_index.get(rule.get("ConfigRuleName")) or {}
        source_identifier = (metadata.get("Source") or {}).get("SourceIdentifier")
        fedramp_controls = mapped_controls(fedramp_mapping, rule.get("ConfigRuleName"), source_identifier)
        nist_controls = mapped_controls(nist_mapping, rule.get("ConfigRuleName"), source_identifier)
        service_controls = rule.get("Controls") or []
        enriched_rules.append({
            **rule,
            "ConfigRuleArn": metadata.get("ConfigRuleArn"),
            "ConfigRuleId": metadata.get("ConfigRuleId"),
            "Source": metadata.get("Source"),
            "Controls": unique(service_controls + fedramp_controls + nist_controls),
            "ServiceControls": service_controls,
            "FedRAMPControls": fedramp_controls,
            "NIST80053Rev5Controls": nist_controls,
        })

    rule_control_mapping = [
        {
            "config_rule_name": rule.get("ConfigRuleName"),
            "source_identifier": (rule.get("Source") or {}).get("SourceIdentifier"),
            "compliance_type": rule.get("ComplianceType"),
            "service_controls": rule["ServiceControls"],
            "fedramp_controls": rule["FedRAMPControls"],
            "nist_800_53_rev_5_controls": rule["NIST80053Rev5Controls"],
            "mapped": bool(rule["FedRAMPControls"]) or bool(rule["NIST80053Rev5Controls"]),
        }
        for rule in enriched_rules
    ]
    fedramp_controls = control_compliance(fedramp_mapping, rule_control_mapping, "fedramp_controls")
    nist_controls = control_compliance(nist_mapping, rule_control_mapping, "nist_800_53_rev_5_controls")

    findings = []
    for evaluation in evaluations:
        if evaluation.get("ComplianceType") != "NON_COMPLIANT":
            continue
        identifier = evaluation.get("EvaluationResultIdentifier") or {}
        qualifier = identifier.get("EvaluationResultQualifier") or {}
        rule_name = qualifier.get("ConfigRuleName")
        source_identifier = source_of(rule_name)
        findings.append({
            "config_rule_name": rule_name,
            "source_identifier": source_identifier,
            "resource_type": qualifier.get("ResourceType"),
            "resource_id": qualifier.get("ResourceId"),
            "compliance_type": evaluation.get("ComplianceType"),
            "fedramp_controls": mapped_controls(fedramp_mapping, rule_name, source_identifier),
            "nist_800_53_rev_5_controls": mapped_controls(nist_mapping, rule_name, source_identifier),
            "annotation": evaluation.get("Annotation"),
            "ordering_timestamp": identifier.get("OrderingTimestamp"),
            "result_recorded_time": evaluation.get("ResultRecordedTime"),
            "config_rule_invoked_time": evaluation.get("ConfigRuleInvokedTime"),
        })

    deployed_names = sorted({
        reference["source_lookup"].get(source_of_rule) or rule.get("ConfigRuleName")
        for rule in config_rule_metadata
        for source_of_rule in [(rule.get("Source") or {}).get("SourceIdentifier") or ""]
    })

    result = {
        "status": state,
        "compliant": counts["COMPLIANT"],
        "non_compliant": counts["NON_COMPLIANT"],
        "insufficient_data": counts["INSUFFICIENT_DATA"],
        "not_applicable": 0,
        "rule_count": len(rules),
        "resource_evaluation_count": len(evaluations),
        "rule_compliance": enriched_rules,
        "aws_rule_compliance": rules,
        "config_rule_metadata": config_rule_metadata,
        "resource_evaluations": evaluations,
        "non_compliant_findings": findings,
        "control_mapping": {
            "rules": rule_control_mapping,
            "fedramp": {
                "framework": fedramp_mapping.get("framework"),
                "aggregation_basis": AGGREGATION_BASIS,
                "controls": fedramp_controls,
            },
            "nist_800_53": {
                "framework": nist_mapping.get("framework"),
                "aggregation_basis": AGGREGATION_BASIS,
                "controls": nist_controls,
            },
        },
        "aws_compliance_summary": summary_doc,
        "template_match": template_match(reference, deployed_names),
    }
    summary = {
        "status": state,
        "total_rules": len(rules),
        "compliant_rules": counts["COMPLIANT"],
        "non_compliant_rules": counts["NON_COMPLIANT"],
        "insufficient_data_rules": counts["INSUFFICIENT_DATA"],
        "non_compliant_resource_evaluations": len(findings),
        "fedramp_controls_assessed": len(fedramp_controls),
        "fedramp_controls_with_non_compliant_rules": sum(
            1 for c in fedramp_controls if c["rule_aggregate_compliance_type"] == "NON_COMPLIANT"),
        "nist_800_53_controls_assessed": len(nist_controls),
        "nist_800_53_controls_with_non_compliant_rules": sum(
            1 for c in nist_controls if c["rule_aggregate_compliance_type"] == "NON_COMPLIANT"),
    }
    return result, summary


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def target_id(profile, region):
    """Same file name as aws_target_id "$REGION" in _shared/aws.sh."""
    target = profile or "ambient"
    if region:
        target = f"{target}_{region}"
    return re.sub(r"[^A-Za-z0-9._-]", "_", target)


class CollectionError(Exception):
    def __init__(self, message, code="partial_failure"):
        super().__init__(message)
        self.code = code


def load_reference(pack):
    """The selected reference template and both control mappings, or a bad_config CollectionError."""
    if pack not in REFERENCES:
        raise CollectionError(f"FEDRAMP_PACK must be either low or moderate (got: {pack or '<unset>'})", "bad_config")
    spec = REFERENCES[pack]
    template = FETCHER_DIR / spec["template"]
    if not template.is_file():
        raise CollectionError(f"selected {pack} reference template is missing: {template}", "bad_config")
    mappings = []
    for path in (FETCHER_DIR / spec["mapping"], FETCHER_DIR / NIST_800_53_MAPPING):
        if not path.is_file():
            raise CollectionError(f"required control mapping is missing: {path}", "bad_config")
        mappings.append(json.loads(path.read_text(encoding="utf-8")))
    template_bytes = template.read_bytes()
    rule_names, source_lookup = reference_rules(template_bytes.decode("utf-8"))
    reference = {
        **spec,
        "rule_names": rule_names,
        "source_lookup": source_lookup,
        "sha256": hashlib.sha256(template_bytes).hexdigest(),
    }
    return reference, mappings[0], mappings[1]


def session_and_client():
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise CollectionError(
            f"boto3 is required for {NAME} (pip install -r requirements.txt)",
            "bad_config",
        ) from exc

    session = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None)
    # The runner maps target.region to AWS_DEFAULT_REGION; pin it so an ambient
    # AWS_REGION cannot override a manifest target.
    region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or session.region_name
    config = Config(
        region_name=region,
        retries={"mode": "standard", "max_attempts": 8},
        connect_timeout=30,
        read_timeout=120,
        max_pool_connections=RULE_WORKERS + 2,
    )
    return session.client("sts", config=config), session.client("config", config=config)


def collect(collector, reference, fedramp_mapping, nist_mapping, region):
    results, summary = {}, {}
    logging.info("Fetching conformance packs...")
    packs = collector.pack_names()
    if not packs:
        logging.info("No conformance packs found in region %s", region)
    for pack in packs:
        logging.info("Processing conformance pack: %s", pack)
        status = collector.pack_status(pack)
        rules_doc = collector.rule_compliance(pack)
        rule_names = sorted({
            rule.get("ConfigRuleName") for rule in rules_doc["ConformancePackRuleComplianceList"]
            if rule.get("ConfigRuleName")
        })
        config_rules_doc = collector.config_rules(rule_names)
        evaluations = collector.resource_evaluations(pack, rule_names)
        summary_doc = collector.compliance_summary(pack)
        results[pack], summary[pack] = pack_result(
            reference, fedramp_mapping, nist_mapping, status, rules_doc, config_rules_doc, evaluations, summary_doc)
        s = summary[pack]
        logging.info("%s -> status: %s | compliant: %s | non-compliant: %s | insufficient-data: %s",
                     pack, s["status"], s["compliant_rules"], s["non_compliant_rules"], s["insufficient_data_rules"])
    return results, summary


def main():
    logging.basicConfig(level=logging.INFO, format=f"%(asctime)s %(levelname)s {NAME} %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")
    logging.Formatter.converter = time.gmtime
    load_dotenv()
    # Recorded in metadata as the target gave them; empty means ambient.
    profile = os.environ.get("AWS_PROFILE", "")
    region = os.environ.get("AWS_DEFAULT_REGION", "")
    fedramp_pack = (os.environ.get("FEDRAMP_PACK") or "low").lower()

    try:
        reference, fedramp_mapping, nist_mapping = load_reference(fedramp_pack)
    except CollectionError as exc:
        report_failure(str(exc), exc.code)
        return 2

    output_dir = Path(os.environ.get("EVIDENCE_DIR", "./evidence"))
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / f"{NAME}_{target_id(profile, region)}.json"

    try:
        sts, config = session_and_client()
    except CollectionError as exc:
        report_failure(str(exc), exc.code)
        return 1
    except Exception as exc:
        report_failure(f"AWS session: {describe(exc)}", classify([describe(exc)]))
        return 1

    collector = Collector(config)
    account_id, arn = "unknown", "unknown"
    try:
        identity = sts.get_caller_identity()
        account_id, arn = identity.get("Account") or "unknown", identity.get("Arn") or "unknown"
    except Exception as exc:
        collector.fail("aws sts get-caller-identity failed", exc)

    evidence = {
        "metadata": {
            "profile": profile,
            "region": region,
            "datetime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "account_id": account_id,
            "arn": arn,
        },
        "selected_fedramp_pack": fedramp_pack,
        "reference_template": {
            "key": reference["key"],
            "name": reference["label"],
            "filename": reference["template"],
            "source_url": reference["source_url"],
            "sha256": reference["sha256"],
            "rule_count": len(reference["rule_names"]),
        },
        "control_mapping_sources": {
            "fedramp": mapping_source(fedramp_mapping),
            "nist_800_53": mapping_source(nist_mapping),
        },
        "results": {},
        "summary": {},
    }
    try:
        evidence["results"], evidence["summary"] = collect(
            collector, reference, fedramp_mapping, nist_mapping, region)
    except Exception as exc:
        report_failure(f"Conformance pack collection failed: {describe(exc)}", "internal_error")
        return 1
    output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    if collector.failures:
        labels = [label for label, _ in collector.failures]
        errors = [error for _, error in collector.failures if error]
        reasons = "; ".join(labels[:3]) + (f"(+{len(labels) - 3} more)" if len(labels) > 3 else "")
        detail = f" -- {' | '.join(errors[:3])}" if errors else ""
        report_failure(f"{len(labels)} AWS API failure(s); first: {reasons}{detail}", classify(errors))
        return 1
    logging.info("Evidence saved to %s", output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
