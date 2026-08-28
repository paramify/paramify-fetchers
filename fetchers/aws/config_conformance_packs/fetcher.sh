#!/bin/bash
# Lists AWS Config conformance packs and collects each pack's deployment status,
# per-rule compliance evaluation results (paginated), and compliant/non-compliant/
# not-applicable rule counts. Ships with Operational-Best-Practices-for-FedRAMP-Low.yaml
# (resolved relative to this script's dir) as a reference conformance pack template.
# Output: $EVIDENCE_DIR/aws_config_conformance_packs.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEDRAMP_LOW_TEMPLATE="$SCRIPT_DIR/Operational-Best-Practices-for-FedRAMP-Low.yaml"

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

# Identity/region come from the AWS CLI credential chain. A manifest target may
# set AWS_PROFILE/AWS_DEFAULT_REGION (multi-account / multi-region fanout); when
# unset, the CLI uses the ambient identity/region. The helper sets PROFILE/REGION
# (for metadata) and provides aws_target_id (for the output filename).
source "$(dirname "$0")/../_shared/aws.sh"

# Per-target output filename (profile+region) so multi-target runs don't overwrite.
_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_config_conformance_packs_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_config_conformance_packs.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_config_conformance_packs_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG"' EXIT

log_info() { printf '%s INFO aws_config_conformance_packs %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_config_conformance_packs %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

CALLER_IDENTITY=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws sts get-caller-identity failed" >> "$_FAILURE_LOG"
    CALLER_IDENTITY='{"Account":"unknown","Arn":"unknown"}'
fi
ACCOUNT_ID=$(echo "$CALLER_IDENTITY" | jq -r '.Account // "unknown"')
ARN=$(echo "$CALLER_IDENTITY" | jq -r '.Arn // "unknown"')
DATETIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
  --arg profile "$PROFILE" --arg region "$REGION" --arg datetime "$DATETIME" \
  --arg account_id "$ACCOUNT_ID" --arg arn "$ARN" \
  '{"metadata": {"profile": $profile, "region": $region, "datetime": $datetime, "account_id": $account_id, "arn": $arn}, "results": {}}' \
  > "$OUTPUT_JSON"

# --- per-script data collection (ported from upstream) ---

[ -f "$FEDRAMP_LOW_TEMPLATE" ] || log_info "FedRAMP Low conformance pack template not found at $FEDRAMP_LOW_TEMPLATE"

log_info "Fetching conformance packs..."
conformance_packs=$(aws configservice describe-conformance-packs \
    \
    \
    --query "ConformancePackDetails[].ConformancePackName" \
    --output json \
    --no-cli-pager 2>/dev/null)
ec=$?
if [ $ec -ne 0 ]; then
    echo "aws configservice describe-conformance-packs failed (exit=$ec)" >> "$_FAILURE_LOG"
    conformance_packs='[]'
fi

# No conformance packs found is valid evidence (AWS Config may not have any packs
# deployed in this region) -- not treated as a failure.
if [ -z "$conformance_packs" ] || [ "$conformance_packs" = "null" ] || [ "$conformance_packs" = "[]" ]; then
    log_info "No conformance packs found in region $REGION"
else
    # Process each conformance pack
    for pack in $(echo "$conformance_packs" | jq -r '.[]'); do
        log_info "Processing conformance pack: $pack"
        compliance_details=$(aws configservice get-conformance-pack-compliance-details \
            \
            \
            --conformance-pack-name "$pack" \
            --output json \
            --no-cli-pager 2>/dev/null)
        ec=$?
        if [ $ec -ne 0 ]; then
            echo "aws configservice get-conformance-pack-compliance-details ($pack) failed (exit=$ec)" >> "$_FAILURE_LOG"
            continue
        fi

        # Initialize combined results
        combined_results="$compliance_details"

        # Handle pagination if necessary
        next_token=$(echo "$compliance_details" | jq -r '.NextToken // empty')
        page_count=1

        while [ ! -z "$next_token" ]; do
            next_page=$(aws configservice get-conformance-pack-compliance-details \
                \
                \
                --conformance-pack-name "$pack" \
                --next-token "$next_token" \
                --output json \
                --no-cli-pager 2>/dev/null)
            ec=$?
            if [ $ec -ne 0 ]; then
                echo "aws configservice get-conformance-pack-compliance-details ($pack page $((page_count + 1))) failed (exit=$ec)" >> "$_FAILURE_LOG"
                break
            fi

            # Combine results
            combined_results=$(echo "$combined_results" | jq -r --argjson next "$next_page" '.ConformancePackRuleEvaluationResults += $next.ConformancePackRuleEvaluationResults')

            # Get next token
            next_token=$(echo "$next_page" | jq -r '.NextToken // empty')
            page_count=$((page_count + 1))

            # Safety check - limit to 50 pages
            if [ $page_count -ge 50 ]; then
                log_info "Reached maximum page limit for $pack"
                break
            fi
        done

        # Use combined results for processing
        compliance_details="$combined_results"

        # Get status details
        status_details=$(aws configservice describe-conformance-pack-status \
            \
            \
            --conformance-pack-names "$pack" \
            --query "ConformancePackStatusDetails[]" \
            --output json \
            --no-cli-pager 2>/dev/null)
        ec=$?
        if [ $ec -ne 0 ]; then
            echo "aws configservice describe-conformance-pack-status ($pack) failed (exit=$ec)" >> "$_FAILURE_LOG"
            continue
        fi

        if [ -z "$status_details" ] || [ "$status_details" = "null" ] || [ "$status_details" = "[]" ]; then
            continue
        fi

        # Get compliance summary
        compliance_summary=$(aws configservice get-conformance-pack-compliance-summary \
            \
            \
            --conformance-pack-names "$pack" \
            --output json \
            --no-cli-pager 2>/dev/null)
        ec=$?
        if [ $ec -ne 0 ]; then
            echo "aws configservice get-conformance-pack-compliance-summary ($pack) failed (exit=$ec)" >> "$_FAILURE_LOG"
            continue
        fi

        if [ -z "$compliance_summary" ] || [ "$compliance_summary" = "null" ] || [ "$compliance_summary" = "[]" ]; then
            continue
        fi

        # Extract values
        status=$(echo "$status_details" | jq -r '.[0].ConformancePackState // "UNKNOWN"')
        compliant=$(echo "$compliance_details" | jq -r '.ConformancePackRuleEvaluationResults[] | select(.ComplianceType == "COMPLIANT") | .EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName' | sort -u | wc -l)
        non_compliant=$(echo "$compliance_details" | jq -r '.ConformancePackRuleEvaluationResults[] | select(.ComplianceType == "NON_COMPLIANT") | .EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName' | sort -u | wc -l)
        not_applicable=$(echo "$compliance_details" | jq -r '.ConformancePackRuleEvaluationResults[] | select(.ComplianceType == "NOT_APPLICABLE") | .EvaluationResultIdentifier.EvaluationResultQualifier.ConfigRuleName' | sort -u | wc -l)

        # Update JSON
        jq --arg pack "$pack" \
           --arg status "$status" \
           --argjson compliant "$compliant" \
           --argjson non_compliant "$non_compliant" \
           --argjson not_applicable "$not_applicable" \
           --argjson details "$compliance_details" \
           '.results[$pack] = {
               "status": $status,
               "compliant": $compliant,
               "non_compliant": $non_compliant,
               "not_applicable": $not_applicable,
               "details": $details
           }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

        # Add summary to JSON
        jq --arg pack "$pack" \
           --arg status "$status" \
           --argjson compliant "$compliant" \
           --argjson non_compliant "$non_compliant" \
           '.summary[$pack] = {
               "status": $status,
               "compliant_rules": $compliant,
               "non_compliant_rules": $non_compliant
           }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

        log_info "$pack -> status: $status | compliant: $compliant | non-compliant: $non_compliant | not-applicable: $not_applicable"
    done
fi

failure_count=$(wc -l < "$_FAILURE_LOG" 2>/dev/null | tr -d ' ')
failure_count=${failure_count:-0}
if [ "$failure_count" -gt 0 ]; then
    # Report WHICH calls failed before the log is discarded on exit; the count
    # alone cannot be acted on. See aws_report_failures in ../_shared/aws.sh.
    aws_report_failures "$_FAILURE_LOG" "$failure_count"
    log_error "Encountered $failure_count AWS API failures during collection"
    exit 1
fi

log_info "Evidence saved to $OUTPUT_JSON"
