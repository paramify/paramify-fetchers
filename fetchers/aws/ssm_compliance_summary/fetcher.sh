#!/bin/bash
# Lists SSM compliance summaries and per-resource compliance status across all
# compliance types to show overall managed-node compliance posture.
# Output: $EVIDENCE_DIR/aws_ssm_compliance_summary.json
# Optional env (else the AWS CLI ambient identity/region): AWS_PROFILE, AWS_DEFAULT_REGION
# Required tools: aws, jq

set -o pipefail

[ -f .env ] && { set -a; . .env; set +a; }

OUTPUT_DIR="${EVIDENCE_DIR:-./evidence}"
mkdir -p "$OUTPUT_DIR"

source "$(dirname "$0")/../_shared/aws.sh"

_TARGET_ID="$(aws_target_id "$REGION")"
OUTPUT_JSON="$OUTPUT_DIR/aws_ssm_compliance_summary_${_TARGET_ID}.json"
_FETCHER_TMP_JSON="$(mktemp -t aws_ssm_compliance_summary.XXXXXX.json)"
_FAILURE_LOG="$(mktemp -t aws_ssm_compliance_summary_fail.XXXXXX)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG"' EXIT

log_info()  { printf '%s INFO  aws_ssm_compliance_summary %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }
log_error() { printf '%s ERROR aws_ssm_compliance_summary %s\n' "$(date -u +'%Y-%m-%d %H:%M:%S')" "$*" >&2; }

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
  '{"metadata":{"profile":$profile,"region":$region,"datetime":$datetime,"account_id":$account_id,"arn":$arn},"results":{"compliance_summaries":[],"resource_compliance_summaries":[],"summary":{}}}' \
  > "$OUTPUT_JSON"

log_info "Collecting SSM compliance summaries"

# Overall compliance summary counts per compliance type.
compliance_summaries=$(aws ssm list-compliance-summaries \
    --query 'ComplianceSummaryItems[*].{ComplianceType:ComplianceType,CompliantSummary:CompliantSummary,NonCompliantSummary:NonCompliantSummary}' \
    --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ssm list-compliance-summaries failed" >> "$_FAILURE_LOG"
    compliance_summaries='[]'
fi

# Per-resource compliance details across all types.
resource_summaries=$(aws ssm list-resource-compliance-summaries \
    --query 'ResourceComplianceSummaryItems[*].{ResourceId:ResourceId,ResourceType:ResourceType,ComplianceType:ComplianceType,Status:Status,OverallSeverity:OverallSeverity}' \
    --output json 2>/dev/null)
if [ $? -ne 0 ]; then
    echo "aws ssm list-resource-compliance-summaries failed" >> "$_FAILURE_LOG"
    resource_summaries='[]'
fi

# Deduplicate by ResourceId: a resource is non-compliant if any of its type
# rows is NON_COMPLIANT; otherwise compliant. This prevents double-counting
# resources that appear once per compliance type.
total_resources=$(echo "$resource_summaries" | jq '[.[].ResourceId] | unique | length')
non_compliant_resources=$(echo "$resource_summaries" | jq '[.[] | select(.Status == "NON_COMPLIANT") | .ResourceId] | unique | length')
compliant_resources=$(echo "$resource_summaries" | jq --argjson nc "$non_compliant_resources" \
    '([.[].ResourceId] | unique | length) - $nc')

_COMP_SUM_JSON="$(mktemp -t aws_ssm_comp_sum.XXXXXX.json)"
_RES_SUM_JSON="$(mktemp -t aws_ssm_res_sum.XXXXXX.json)"
trap 'rm -f "$_FETCHER_TMP_JSON" "$_FAILURE_LOG" "$_AWS_ERR_LOG" "$_COMP_SUM_JSON" "$_RES_SUM_JSON"' EXIT
printf '%s' "$compliance_summaries" > "$_COMP_SUM_JSON"
printf '%s' "$resource_summaries"   > "$_RES_SUM_JSON"

jq --slurpfile comp_sum "$_COMP_SUM_JSON" \
   --slurpfile res_sum  "$_RES_SUM_JSON" \
   --arg total         "$total_resources" \
   --arg compliant     "$compliant_resources" \
   --arg non_compliant "$non_compliant_resources" \
   '.results = {
       "compliance_summaries": ($comp_sum[0] // []),
       "resource_compliance_summaries": ($res_sum[0] // []),
       "summary": {
         "total_resources":         ($total         | tonumber),
         "compliant_resources":     ($compliant     | tonumber),
         "non_compliant_resources": ($non_compliant | tonumber)
       }
   }' "$OUTPUT_JSON" > "$_FETCHER_TMP_JSON" && mv "$_FETCHER_TMP_JSON" "$OUTPUT_JSON"

log_info "Evidence saved to $OUTPUT_JSON (distinct resources: $total_resources, compliant: $compliant_resources, non-compliant: $non_compliant_resources)"

aws_finish
