#!/bin/bash
# Lists AWS Config conformance packs and collects deployment status, rule-level
# compliance, and resource-level evaluation results. FEDRAMP_PACK (low|moderate)
# selects the bundled reference conformance pack used for rule-set comparison.
# Output: $EVIDENCE_DIR/aws_config_conformance_packs_<target>.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq, awk, sort, comm

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEDRAMP_LOW_TEMPLATE="$SCRIPT_DIR/Operational-Best-Practices-for-FedRAMP-Low.yaml"
FEDRAMP_MODERATE_TEMPLATE="$SCRIPT_DIR/Operational-Best-Practices-for-FedRAMP-Moderate.yaml"
FEDRAMP_LOW_CONTROL_MAPPING="$SCRIPT_DIR/control_mappings/fedramp_low.json"
FEDRAMP_MODERATE_CONTROL_MAPPING="$SCRIPT_DIR/control_mappings/fedramp_moderate.json"
NIST_800_53_CONTROL_MAPPING="$SCRIPT_DIR/control_mappings/nist_800_53_rev_5.json"

FEDRAMP_PACK="$(printf '%s' "${FEDRAMP_PACK:-low}" | tr '[:upper:]' '[:lower:]')"
case "$FEDRAMP_PACK" in
    low)
        REFERENCE_KEY="fedramp_low"
        REFERENCE_LABEL="Operational Best Practices for FedRAMP (Low)"
        REFERENCE_TEMPLATE="$FEDRAMP_LOW_TEMPLATE"
        FEDRAMP_CONTROL_MAPPING="$FEDRAMP_LOW_CONTROL_MAPPING"
        REFERENCE_SOURCE_URL="https://github.com/awslabs/aws-config-rules/blob/master/aws-config-conformance-packs/Operational-Best-Practices-for-FedRAMP-Low.yaml"
        ;;
    moderate)
        REFERENCE_KEY="fedramp_moderate"
        REFERENCE_LABEL="Operational Best Practices for FedRAMP (Moderate)"
        REFERENCE_TEMPLATE="$FEDRAMP_MODERATE_TEMPLATE"
        FEDRAMP_CONTROL_MAPPING="$FEDRAMP_MODERATE_CONTROL_MAPPING"
        REFERENCE_SOURCE_URL="https://github.com/awslabs/aws-config-rules/blob/master/aws-config-conformance-packs/Operational-Best-Practices-for-FedRAMP.yaml"
        ;;
    *)
        printf 'FEDRAMP_PACK must be either low or moderate (got: %s)\n' "${FEDRAMP_PACK:-<unset>}" >&2
        exit 2
        ;;
esac

if [ ! -f "$REFERENCE_TEMPLATE" ]; then
    printf 'Selected %s reference template is missing: %s\n' "$FEDRAMP_PACK" "$REFERENCE_TEMPLATE" >&2
    if [ "$FEDRAMP_PACK" = "moderate" ]; then
        printf 'Run %s/sync_reference_templates.sh once to vendor the official AWS Moderate template.\n' "$SCRIPT_DIR" >&2
    fi
    exit 2
fi

for mapping_file in "$FEDRAMP_CONTROL_MAPPING" "$NIST_800_53_CONTROL_MAPPING"; do
    if [ ! -f "$mapping_file" ]; then
        printf 'Required control mapping is missing: %s\n' "$mapping_file" >&2
        printf 'Run %s/sync_control_mappings.py to vendor the official AWS mappings.\n' "$SCRIPT_DIR" >&2
        exit 2
    fi
done

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Identity/region come from the AWS CLI credential chain. A manifest target may
# set AWS_PROFILE/AWS_DEFAULT_REGION (multi-account / multi-region fanout); when
# unset, the CLI uses the ambient identity/region. The helper sets PROFILE/REGION
# (for metadata) and provides aws_target_id (for the output filename).
source "$(dirname "$0")/../_shared/aws.sh"

_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_config_conformance_packs_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_config_conformance_packs.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_config_conformance_packs_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info() { printf '%s INFO aws_config_conformance_packs %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_config_conformance_packs %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
record_failure() { printf '%s\n' "$*" >> "$_FAILURE_LOG"; }

# Fetch raw API pages explicitly instead of relying on AWS CLI auto-pagination.
fetch_rule_compliance_pages() {
    local pack="$1" output_file="$2"
    local page_file="$_TMP_DIR/rule_compliance_page.json"
    local merge_file="$_TMP_DIR/rule_compliance_merge.json"
    local next_token="" previous_token="" request_json
    local page_count=1 ec

    jq -n --arg pack "$pack" '{ConformancePackName: $pack, ConformancePackRuleComplianceList: []}' > "$output_file"
    while :; do
        request_json=$(jq -cn --arg pack "$pack" --arg token "$next_token" \
          '{ConformancePackName: $pack, Limit: 1000}
           + if $token == "" then {} else {NextToken: $token} end')
        aws configservice describe-conformance-pack-compliance \
            --cli-input-json "$request_json" --no-paginate \
            --output json --no-cli-pager > "$page_file" 2>/dev/null
        ec=$?
        if [ $ec -ne 0 ]; then
            record_failure "aws configservice describe-conformance-pack-compliance ($pack page $page_count) failed (exit=$ec)"
            return 1
        fi
        if ! jq -s '
          .[0] as $all | .[1] as $page |
          {ConformancePackName: ($page.ConformancePackName // $all.ConformancePackName),
           ConformancePackRuleComplianceList:
             (($all.ConformancePackRuleComplianceList // []) + ($page.ConformancePackRuleComplianceList // []))}
        ' "$output_file" "$page_file" > "$merge_file"; then
            record_failure "invalid describe-conformance-pack-compliance response ($pack page $page_count)"
            return 1
        fi
        mv "$merge_file" "$output_file"
        next_token=$(jq -r '.NextToken // empty' "$page_file")
        [ -z "$next_token" ] && break
        if [ "$next_token" = "$previous_token" ]; then
            record_failure "describe-conformance-pack-compliance ($pack) returned a repeated NextToken"
            return 1
        fi
        previous_token="$next_token"
        page_count=$((page_count + 1))
    done
}

# Resolve deployed (and often suffixed) ConfigRuleName values to stable managed
# rule SourceIdentifier values. DescribeConfigRules accepts at most 25 names.
fetch_config_rule_metadata() {
    local rules_file="$1" output_file="$2"
    local page_file="$_TMP_DIR/config_rules_page.json"
    local merge_file="$_TMP_DIR/config_rules_merge.json"
    local names_json request_json next_token previous_token
    local page_count ec offset
    local had_failure=0
    local -a rule_names batch

    jq -n '{ConfigRules: []}' > "$output_file"
    # macOS still ships Bash 3.2, which has indexed arrays but no mapfile.
    # Populate the array with a read loop so the fetcher works with every Bash
    # version supported by the repository.
    while IFS= read -r rule_name; do
        [ -n "$rule_name" ] && rule_names[${#rule_names[@]}]="$rule_name"
    done < <(jq -r '.ConformancePackRuleComplianceList[]?.ConfigRuleName' "$rules_file" | sort -u)

    for ((offset = 0; offset < ${#rule_names[@]}; offset += 25)); do
        batch=("${rule_names[@]:offset:25}")
        names_json=$(printf '%s\n' "${batch[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')
        next_token=""
        previous_token=""
        page_count=1

        while :; do
            request_json=$(jq -cn --argjson names "$names_json" --arg token "$next_token" \
              '{ConfigRuleNames: $names}
               + if $token == "" then {} else {NextToken: $token} end')
            aws configservice describe-config-rules \
                --cli-input-json "$request_json" --no-paginate \
                --output json --no-cli-pager > "$page_file" 2>/dev/null
            ec=$?
            if [ $ec -ne 0 ]; then
                record_failure "aws configservice describe-config-rules (batch $((offset / 25 + 1)) page $page_count) failed (exit=$ec)"
                had_failure=1
                break
            fi
            if ! jq -s '
              .[0] as $all | .[1] as $page |
              {ConfigRules: (($all.ConfigRules // []) + ($page.ConfigRules // []))}
            ' "$output_file" "$page_file" > "$merge_file"; then
                record_failure "invalid describe-config-rules response (batch $((offset / 25 + 1)) page $page_count)"
                had_failure=1
                break
            fi
            mv "$merge_file" "$output_file"
            next_token=$(jq -r '.NextToken // empty' "$page_file")
            [ -z "$next_token" ] && break
            if [ "$next_token" = "$previous_token" ]; then
                record_failure "describe-config-rules returned a repeated NextToken"
                had_failure=1
                break
            fi
            previous_token="$next_token"
            page_count=$((page_count + 1))
        done
    done
    return "$had_failure"
}

# Query every rule separately, then exhaust that rule's NextToken chain.
fetch_resource_evaluation_pages() {
    local pack="$1" rules_file="$2" output_file="$3"
    local page_file="$_TMP_DIR/resource_evaluations_page.json"
    local merge_file="$_TMP_DIR/resource_evaluations_merge.json"
    local rule next_token previous_token request_json page_count ec
    local had_failure=0

    jq -n --arg pack "$pack" '{ConformancePackName: $pack, ConformancePackRuleEvaluationResults: []}' > "$output_file"
    while IFS= read -r rule; do
        [ -z "$rule" ] && continue
        next_token=""
        previous_token=""
        page_count=1
        while :; do
            request_json=$(jq -cn --arg pack "$pack" --arg rule "$rule" --arg token "$next_token" \
              '{ConformancePackName: $pack, Filters: {ConfigRuleNames: [$rule]}, Limit: 100}
               + if $token == "" then {} else {NextToken: $token} end')
            aws configservice get-conformance-pack-compliance-details \
                --cli-input-json "$request_json" --no-paginate \
                --output json --no-cli-pager > "$page_file" 2>/dev/null
            ec=$?
            if [ $ec -ne 0 ]; then
                record_failure "aws configservice get-conformance-pack-compliance-details ($pack rule $rule page $page_count) failed (exit=$ec)"
                had_failure=1
                break
            fi
            if ! jq -s '
              .[0] as $all | .[1] as $page |
              {ConformancePackName: ($page.ConformancePackName // $all.ConformancePackName),
               ConformancePackRuleEvaluationResults:
                 (($all.ConformancePackRuleEvaluationResults // []) + ($page.ConformancePackRuleEvaluationResults // []))}
            ' "$output_file" "$page_file" > "$merge_file"; then
                record_failure "invalid get-conformance-pack-compliance-details response ($pack rule $rule page $page_count)"
                had_failure=1
                break
            fi
            mv "$merge_file" "$output_file"
            next_token=$(jq -r '.NextToken // empty' "$page_file")
            [ -z "$next_token" ] && break
            if [ "$next_token" = "$previous_token" ]; then
                record_failure "get-conformance-pack-compliance-details ($pack rule $rule) returned a repeated NextToken"
                had_failure=1
                break
            fi
            previous_token="$next_token"
            page_count=$((page_count + 1))
        done
    done < <(jq -r '.ConformancePackRuleComplianceList[]?.ConfigRuleName' "$rules_file" | sort -u)
    return "$had_failure"
}

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    record_failure "aws sts get-caller-identity failed"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  '{
    "metadata": {
      "profile": $profile,
      "region": $region,
      "datetime": $datetime,
      "account_id": $account_id,
      "arn": $arn
    },
    "selected_fedramp_pack": null,
    "reference_template": {},
    "control_mapping_sources": {},
    "results": {},
    "summary": {}
  }' > "$OUTPUT_JSON"

# Build a compact rule-name index for the selected bundled reference template.
# No YAML parser is required because ConfigRuleName is a stable scalar in AWS's templates.
REFERENCE_RULES_FILE="$_TMP_DIR/reference_rules.txt"
awk '/^[[:space:]]+ConfigRuleName:[[:space:]]*/ {
  sub(/^[[:space:]]+ConfigRuleName:[[:space:]]*/, "")
  sub(/\r$/, "")
  print
}' "$REFERENCE_TEMPLATE" | sort -u > "$REFERENCE_RULES_FILE"
REFERENCE_SOURCE_LOOKUP_FILE="$_TMP_DIR/reference_source_lookup.json"
awk '
  /^[[:space:]]+ConfigRuleName:[[:space:]]*/ {
    rule = $0
    sub(/^[[:space:]]+ConfigRuleName:[[:space:]]*/, "", rule)
    sub(/\r$/, "", rule)
  }
  /^[[:space:]]+SourceIdentifier:[[:space:]]*/ {
    source = $0
    sub(/^[[:space:]]+SourceIdentifier:[[:space:]]*/, "", source)
    sub(/\r$/, "", source)
    if (rule != "") print source "\t" rule
    rule = ""
  }
' "$REFERENCE_TEMPLATE" |
  jq -Rn '[inputs | split("\t") | select(length >= 2) | {(.[0]): .[1]}] | add // {}' \
  > "$REFERENCE_SOURCE_LOOKUP_FILE"
reference_rule_count=$(wc -l < "$REFERENCE_RULES_FILE" | tr -d ' ')
if command -v sha256sum >/dev/null 2>&1; then
    reference_sha256=$(sha256sum "$REFERENCE_TEMPLATE" | awk '{print $1}')
else
    reference_sha256="unknown"
fi

jq \
  --arg pack "$FEDRAMP_PACK" \
  --arg key "$REFERENCE_KEY" \
  --arg label "$REFERENCE_LABEL" \
  --arg file "$(basename "$REFERENCE_TEMPLATE")" \
  --arg source_url "$REFERENCE_SOURCE_URL" \
  --arg sha256 "$reference_sha256" \
  --argjson rule_count "$reference_rule_count" \
  --slurpfile fedramp_mapping "$FEDRAMP_CONTROL_MAPPING" \
  --slurpfile nist_mapping "$NIST_800_53_CONTROL_MAPPING" \
  '.selected_fedramp_pack = $pack |
   .reference_template = {
      "key": $key,
      "name": $label,
      "filename": $file,
      "source_url": $source_url,
      "sha256": $sha256,
      "rule_count": $rule_count
   } |
   .control_mapping_sources = {
      "fedramp": {
        "framework": $fedramp_mapping[0].framework,
        "title": $fedramp_mapping[0].title,
        "source_url": $fedramp_mapping[0].source_url,
        "rule_count": $fedramp_mapping[0].rule_count,
        "control_count": $fedramp_mapping[0].control_count,
        "disclaimer": $fedramp_mapping[0].disclaimer
      },
      "nist_800_53": {
        "framework": $nist_mapping[0].framework,
        "title": $nist_mapping[0].title,
        "source_url": $nist_mapping[0].source_url,
        "rule_count": $nist_mapping[0].rule_count,
        "control_count": $nist_mapping[0].control_count,
        "disclaimer": $nist_mapping[0].disclaimer
      }
   }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "Fetching conformance packs..."
PACKS_FILE="$_TMP_DIR/conformance_packs.json"
aws configservice describe-conformance-packs \
    --output json \
    --no-cli-pager > "$PACKS_FILE" 2>/dev/null
ec=$?
if [ $ec -ne 0 ]; then
    record_failure "aws configservice describe-conformance-packs failed (exit=$ec)"
    echo '{"ConformancePackDetails":[]}' > "$PACKS_FILE"
fi

conformance_packs=$(jq -r '.ConformancePackDetails[]?.ConformancePackName' "$PACKS_FILE")
if [ -z "$conformance_packs" ]; then
    log_info "No conformance packs found in region $REGION"
else
    while IFS= read -r pack; do
        [ -z "$pack" ] && continue
        log_info "Processing conformance pack: $pack"

        safe_pack=$(printf '%s' "$pack" | tr -c 'A-Za-z0-9._-' '_')
        STATUS_FILE="$_TMP_DIR/${safe_pack}_status.json"
        SUMMARY_FILE="$_TMP_DIR/${safe_pack}_summary.json"
        RULES_FILE="$_TMP_DIR/${safe_pack}_rule_compliance.json"
        CONFIG_RULES_FILE="$_TMP_DIR/${safe_pack}_config_rules.json"
        DETAILS_FILE="$_TMP_DIR/${safe_pack}_resource_details.json"
        TEMPLATE_MATCH_FILE="$_TMP_DIR/${safe_pack}_template_match.json"

        aws configservice describe-conformance-pack-status \
            --conformance-pack-names "$pack" \
            --query 'ConformancePackStatusDetails' \
            --output json \
            --no-cli-pager > "$STATUS_FILE" 2>/dev/null
        ec=$?
        if [ $ec -ne 0 ]; then
            record_failure "aws configservice describe-conformance-pack-status ($pack) failed (exit=$ec)"
            echo '[]' > "$STATUS_FILE"
        fi

        # Rule-level compliance is the authoritative source for COMPLIANT /
        # NON_COMPLIANT / INSUFFICIENT_DATA counts. Consume every API page.
        fetch_rule_compliance_pages "$pack" "$RULES_FILE"
        ec=$?
        if [ $ec -ne 0 ]; then
            log_error "Rule-compliance pagination failed for $pack"
        fi

        # Conformance pack rules are deployed with generated name suffixes.
        # Resolve them to stable Source.SourceIdentifier values for matching.
        fetch_config_rule_metadata "$RULES_FILE" "$CONFIG_RULES_FILE"
        ec=$?
        if [ $ec -ne 0 ]; then
            log_error "Config rule metadata collection failed for $pack"
        fi

        # Resource-level evaluations provide the actual affected resource IDs,
        # annotations and timestamps. Paginate independently for every rule.
        fetch_resource_evaluation_pages "$pack" "$RULES_FILE" "$DETAILS_FILE"
        ec=$?
        if [ $ec -ne 0 ]; then
            log_error "Resource-evaluation pagination failed for one or more rules in $pack"
        fi

        aws configservice get-conformance-pack-compliance-summary \
            --conformance-pack-names "$pack" \
            --output json \
            --no-cli-pager > "$SUMMARY_FILE" 2>/dev/null
        ec=$?
        if [ $ec -ne 0 ]; then
            record_failure "aws configservice get-conformance-pack-compliance-summary ($pack) failed (exit=$ec)"
            echo '{"ConformancePackComplianceSummaryList":[]}' > "$SUMMARY_FILE"
        fi

        # Compare deployed rule names with the selected FedRAMP reference pack.
        DEPLOYED_RULES_FILE="$_TMP_DIR/${safe_pack}_deployed_rules.txt"
        OVERLAP_FILE="$_TMP_DIR/${safe_pack}_overlap.txt"
        MISSING_FILE="$_TMP_DIR/${safe_pack}_missing.txt"
        EXTRA_FILE="$_TMP_DIR/${safe_pack}_extra.txt"
        jq -r --slurpfile reference_lookup "$REFERENCE_SOURCE_LOOKUP_FILE" '
          ($reference_lookup[0] // {}) as $lookup |
          .ConfigRules[]? |
          (.Source.SourceIdentifier // "") as $source_identifier |
          if $lookup[$source_identifier] then $lookup[$source_identifier]
          else .ConfigRuleName
          end
        ' "$CONFIG_RULES_FILE" | sort -u > "$DEPLOYED_RULES_FILE"
        # Native Windows jq writes CRLF even when called from Git/MSYS Bash.
        # Remove carriage returns before comm compares the generated list with
        # the LF-normalized vendored template.
        tr -d '\r' < "$DEPLOYED_RULES_FILE" > "$_TMP_DIR/${safe_pack}_deployed_rules_lf.txt"
        mv "$_TMP_DIR/${safe_pack}_deployed_rules_lf.txt" "$DEPLOYED_RULES_FILE"
        comm -12 "$DEPLOYED_RULES_FILE" "$REFERENCE_RULES_FILE" > "$OVERLAP_FILE"
        comm -13 "$DEPLOYED_RULES_FILE" "$REFERENCE_RULES_FILE" > "$MISSING_FILE"
        comm -23 "$DEPLOYED_RULES_FILE" "$REFERENCE_RULES_FILE" > "$EXTRA_FILE"

        deployed_count=$(wc -l < "$DEPLOYED_RULES_FILE" | tr -d ' ')
        overlap_count=$(wc -l < "$OVERLAP_FILE" | tr -d ' ')
        missing_count=$(wc -l < "$MISSING_FILE" | tr -d ' ')
        extra_count=$(wc -l < "$EXTRA_FILE" | tr -d ' ')
        if [ "$reference_rule_count" -gt 0 ]; then
            coverage=$(awk -v a="$overlap_count" -v b="$reference_rule_count" 'BEGIN {printf "%.2f", (a/b)*100}')
        else
            coverage="0.00"
        fi

        if ! jq -n --arg key "$REFERENCE_KEY" \
           --argjson deployed_count "$deployed_count" \
           --argjson template_count "$reference_rule_count" \
           --argjson overlap_count "$overlap_count" \
           --argjson missing_count "$missing_count" \
           --argjson extra_count "$extra_count" \
           --arg coverage "$coverage" \
           --rawfile missing "$MISSING_FILE" \
           --rawfile extra "$EXTRA_FILE" \
           '{
              "reference": $key,
              "comparison_key": "Source.SourceIdentifier",
              "deployed_rule_count": $deployed_count,
              "template_rule_count": $template_count,
              "matching_rule_count": $overlap_count,
              "coverage_percent": ($coverage | tonumber),
              "missing_template_rules_count": $missing_count,
              "extra_deployed_rules_count": $extra_count,
              "missing_template_rules": ($missing | split("\n") | map(select(length > 0))),
              "extra_deployed_rules": ($extra | split("\n") | map(select(length > 0)))
            }' > "$TEMPLATE_MATCH_FILE"; then
            record_failure "failed to build template comparison for $pack"
            echo '{}' > "$TEMPLATE_MATCH_FILE"
        fi

        # IMPORTANT: large AWS Config payloads are loaded from files with
        # --slurpfile. Passing them via --argjson can exceed the OS argument-size
        # limit for Moderate packs and was the reason .results could stay empty
        # while .summary was still written.
        jq \
          --arg pack "$pack" \
          --slurpfile status_doc "$STATUS_FILE" \
          --slurpfile rules_doc "$RULES_FILE" \
          --slurpfile config_rules_doc "$CONFIG_RULES_FILE" \
          --slurpfile details_doc "$DETAILS_FILE" \
          --slurpfile summary_doc "$SUMMARY_FILE" \
          --slurpfile template_match_doc "$TEMPLATE_MATCH_FILE" \
          --slurpfile fedramp_mapping_doc "$FEDRAMP_CONTROL_MAPPING" \
          --slurpfile nist_mapping_doc "$NIST_800_53_CONTROL_MAPPING" \
          '
          def aggregate_compliance($mapped_rules):
            if any($mapped_rules[]; .compliance_type == "NON_COMPLIANT") then "NON_COMPLIANT"
            elif any($mapped_rules[]; .compliance_type == "INSUFFICIENT_DATA") then "INSUFFICIENT_DATA"
            elif all($mapped_rules[]; .compliance_type == "COMPLIANT") then "COMPLIANT"
            else "UNKNOWN"
            end;
          def source_rule_name($source_identifier):
            ($source_identifier // "") as $source |
            if ($source | test("^[A-Z0-9_]+$"))
            then ($source | ascii_downcase | gsub("_"; "-"))
            else ""
            end;
          def controls_by_name($mapping; $rule_name):
            ($rule_name // "") as $name |
            ($mapping.rules[$name]
             // $mapping.rules[($mapping.aliases[$name] // $name)]);
          def mapped_controls($mapping; $rule_name; $source_identifier):
            source_rule_name($source_identifier) as $source_name |
            ($rule_name | sub("-conformance-pack-[a-z0-9-]+$"; "")) as $base_rule_name |
            (controls_by_name($mapping; $source_name)
             // controls_by_name($mapping; $base_rule_name)
             // []);

          ($status_doc[0] // []) as $status |
          ($rules_doc[0].ConformancePackRuleComplianceList // []) as $rules |
          ($config_rules_doc[0].ConfigRules // []) as $config_rule_metadata |
          ($config_rule_metadata | map({key: .ConfigRuleName, value: .}) | from_entries) as $config_rule_index |
          ($details_doc[0].ConformancePackRuleEvaluationResults // []) as $evaluations |
          ($summary_doc[0] // {}) as $aws_summary |
          ($template_match_doc[0] // {}) as $template_match |
          ($fedramp_mapping_doc[0] // {}) as $fedramp_mapping |
          ($nist_mapping_doc[0] // {}) as $nist_mapping |
          ($status[0].ConformancePackState // "UNKNOWN") as $state |
          ([ $rules[] | select(.ComplianceType == "COMPLIANT") ] | length) as $compliant |
          ([ $rules[] | select(.ComplianceType == "NON_COMPLIANT") ] | length) as $non_compliant |
          ([ $rules[] | select(.ComplianceType == "INSUFFICIENT_DATA") ] | length) as $insufficient_data |
          ([ $rules[] |
             . as $rule |
             ($config_rule_index[$rule.ConfigRuleName] // {}) as $rule_metadata |
             ($rule_metadata.Source.SourceIdentifier // null) as $source_identifier |
             mapped_controls($fedramp_mapping; $rule.ConfigRuleName; $source_identifier) as $fedramp_controls |
             mapped_controls($nist_mapping; $rule.ConfigRuleName; $source_identifier) as $nist_controls |
             ($rule.Controls // []) as $service_controls |
             $rule + {
               "ConfigRuleArn": ($rule_metadata.ConfigRuleArn // null),
               "ConfigRuleId": ($rule_metadata.ConfigRuleId // null),
               "Source": ($rule_metadata.Source // null),
               "Controls": (($service_controls + $fedramp_controls + $nist_controls) | unique),
               "ServiceControls": $service_controls,
               "FedRAMPControls": $fedramp_controls,
               "NIST80053Rev5Controls": $nist_controls
             }
           ]) as $enriched_rules |
          ([ $enriched_rules[] |
             . as $rule |
             {
               "config_rule_name": $rule.ConfigRuleName,
               "source_identifier": ($rule.Source.SourceIdentifier // null),
               "compliance_type": $rule.ComplianceType,
               "service_controls": $rule.ServiceControls,
               "fedramp_controls": $rule.FedRAMPControls,
               "nist_800_53_rev_5_controls": $rule.NIST80053Rev5Controls,
               "mapped": (($rule.FedRAMPControls | length) > 0 or ($rule.NIST80053Rev5Controls | length) > 0)
             }
           ]) as $rule_control_mapping |
          ([ ($fedramp_mapping.controls // {}) | to_entries[] |
             . as $control |
             ([ $rule_control_mapping[] |
                select(.fedramp_controls | index($control.key)) |
                {"config_rule_name": .config_rule_name, "compliance_type": .compliance_type}
              ]) as $mapped_rules |
             select(($mapped_rules | length) > 0) |
             {
               "control_id": $control.key,
               "description": $control.value.description,
               "rule_aggregate_compliance_type": aggregate_compliance($mapped_rules),
               "config_rules": $mapped_rules
             }
           ]) as $fedramp_control_compliance |
          ([ ($nist_mapping.controls // {}) | to_entries[] |
             . as $control |
             ([ $rule_control_mapping[] |
                select(.nist_800_53_rev_5_controls | index($control.key)) |
                {"config_rule_name": .config_rule_name, "compliance_type": .compliance_type}
              ]) as $mapped_rules |
             select(($mapped_rules | length) > 0) |
             {
               "control_id": $control.key,
               "description": $control.value.description,
               "rule_aggregate_compliance_type": aggregate_compliance($mapped_rules),
               "config_rules": $mapped_rules
             }
           ]) as $nist_control_compliance |
          ([ $evaluations[] | select(.ComplianceType == "NON_COMPLIANT") |
            .EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName as $rule_name |
            ($config_rule_index[$rule_name].Source.SourceIdentifier // null) as $source_identifier |
            {
              "config_rule_name": $rule_name,
              "source_identifier": $source_identifier,
              "resource_type": .EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType,
              "resource_id": .EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,
              "compliance_type": .ComplianceType,
              "fedramp_controls": mapped_controls($fedramp_mapping; $rule_name; $source_identifier),
              "nist_800_53_rev_5_controls": mapped_controls($nist_mapping; $rule_name; $source_identifier),
              "annotation": (.Annotation // null),
              "ordering_timestamp": (.EvaluationResultIdentifier.OrderingTimestamp // null),
              "result_recorded_time": (.ResultRecordedTime // null),
              "config_rule_invoked_time": (.ConfigRuleInvokedTime // null)
            } ]) as $findings |
          .results[$pack] = {
              "status": $state,
              "compliant": $compliant,
              "non_compliant": $non_compliant,
              "insufficient_data": $insufficient_data,
              "not_applicable": 0,
              "rule_count": ($rules | length),
              "resource_evaluation_count": ($evaluations | length),
              "rule_compliance": $enriched_rules,
              "aws_rule_compliance": $rules,
              "config_rule_metadata": $config_rule_metadata,
              "resource_evaluations": $evaluations,
              "non_compliant_findings": $findings,
              "control_mapping": {
                "rules": $rule_control_mapping,
                "fedramp": {
                  "framework": $fedramp_mapping.framework,
                  "aggregation_basis": "DEPLOYED_MAPPED_CONFIG_RULES",
                  "controls": $fedramp_control_compliance
                },
                "nist_800_53": {
                  "framework": $nist_mapping.framework,
                  "aggregation_basis": "DEPLOYED_MAPPED_CONFIG_RULES",
                  "controls": $nist_control_compliance
                }
              },
              "aws_compliance_summary": $aws_summary,
              "template_match": $template_match
          } |
          .summary[$pack] = {
              "status": $state,
              "total_rules": ($rules | length),
              "compliant_rules": $compliant,
              "non_compliant_rules": $non_compliant,
              "insufficient_data_rules": $insufficient_data,
              "non_compliant_resource_evaluations": ($findings | length),
              "fedramp_controls_assessed": ($fedramp_control_compliance | length),
              "fedramp_controls_with_non_compliant_rules":
                ([ $fedramp_control_compliance[] |
                   select(.rule_aggregate_compliance_type == "NON_COMPLIANT") ] | length),
              "nist_800_53_controls_assessed": ($nist_control_compliance | length),
              "nist_800_53_controls_with_non_compliant_rules":
                ([ $nist_control_compliance[] |
                   select(.rule_aggregate_compliance_type == "NON_COMPLIANT") ] | length)
          }
          ' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

        compliant=$(jq -r --arg pack "$pack" '.summary[$pack].compliant_rules // 0' "$OUTPUT_JSON")
        non_compliant=$(jq -r --arg pack "$pack" '.summary[$pack].non_compliant_rules // 0' "$OUTPUT_JSON")
        insufficient_data=$(jq -r --arg pack "$pack" '.summary[$pack].insufficient_data_rules // 0' "$OUTPUT_JSON")
        status=$(jq -r --arg pack "$pack" '.summary[$pack].status // "UNKNOWN"' "$OUTPUT_JSON")
        log_info "$pack -> status: $status | compliant: $compliant | non-compliant: $non_compliant | insufficient-data: $insufficient_data"
    done <<< "$conformance_packs"
fi

failure_count=$(wc -l < "$_FAILURE_LOG" 2>/dev/null | tr -d ' ')
failure_count=${failure_count:-0}
if [ "$failure_count" -gt 0 ]; then
    _reasons="$(head -n 3 "$_FAILURE_LOG" | awk '{printf "%s%s", sep, $0; sep="; "}')"
    [ "$failure_count" -gt 3 ] && _reasons="${_reasons}(+$((failure_count - 3)) more)"
    aws_report_failures "$failure_count" "$_reasons"
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
